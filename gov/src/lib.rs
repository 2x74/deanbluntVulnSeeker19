use std::fs;

#[repr(C)]
pub struct GovOut {
    pub cpu_pct: u32,
    pub mem_pct: u32,
    pub target: u32,
    pub throttled: u32,
    pub psi_mem_x100: u32,
}

pub struct Gov {
    cpu_cap: u32,
    mem_cap: u32,
    prev_total: u64,
    prev_idle: u64,
    over_streak: u32,
    calm_streak: u32,
    target: u32,
    throttled: bool,
}

fn read_cpu() -> Option<(u64, u64)> {
    let s = fs::read_to_string("/proc/stat").ok()?;
    let line = s.lines().next()?;
    let mut it = line.split_whitespace();
    if it.next()? != "cpu" {
        return None;
    }
    let v: Vec<u64> = it.filter_map(|x| x.parse().ok()).collect();
    if v.len() < 5 {
        return None;
    }
    let total: u64 = v.iter().take(8).sum();
    let idle = v[3] + v[4];
    Some((total, idle))
}

fn kb(r: &str) -> u64 {
    r.split_whitespace()
        .next()
        .and_then(|x| x.parse().ok())
        .unwrap_or(0)
}

fn read_mem() -> Option<u32> {
    let s = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = 0u64;
    let mut avail = 0u64;
    for l in s.lines() {
        if let Some(r) = l.strip_prefix("MemTotal:") {
            total = kb(r);
        } else if let Some(r) = l.strip_prefix("MemAvailable:") {
            avail = kb(r);
        }
    }
    if total == 0 {
        return None;
    }
    let used = total.saturating_sub(avail);
    Some(((used * 100) / total) as u32)
}

fn read_psi_mem() -> u32 {
    let s = match fs::read_to_string("/proc/pressure/memory") {
        Ok(s) => s,
        Err(_) => return 0,
    };
    for l in s.lines() {
        if let Some(r) = l.strip_prefix("full ") {
            for tok in r.split_whitespace() {
                if let Some(v) = tok.strip_prefix("avg10=") {
                    return (v.parse::<f64>().unwrap_or(0.0) * 100.0) as u32;
                }
            }
        }
    }
    0
}

impl Gov {
    fn new(cpu_cap: u32, mem_cap: u32) -> Gov {
        let (t, i) = read_cpu().unwrap_or((0, 0));
        Gov {
            cpu_cap: cpu_cap.clamp(1, 100),
            mem_cap: mem_cap.clamp(1, 100),
            prev_total: t,
            prev_idle: i,
            over_streak: 0,
            calm_streak: 0,
            target: 0,
            throttled: false,
        }
    }

    fn poll(&mut self, total: u32) -> GovOut {
        let cpu = match read_cpu() {
            Some((t, i)) => {
                let dt = t.saturating_sub(self.prev_total);
                let di = i.saturating_sub(self.prev_idle);
                self.prev_total = t;
                self.prev_idle = i;
                if dt == 0 {
                    0
                } else {
                    (100 * dt.saturating_sub(di) / dt) as u32
                }
            }
            None => 0,
        };
        let mem = read_mem().unwrap_or(0);
        let psi = read_psi_mem();

        if self.target == 0 || self.target > total {
            self.target = total;
        }

        let cpu_over = cpu >= self.cpu_cap;
        let mem_over = mem >= self.mem_cap || psi >= 500;
        let calm = cpu + 7 <= self.cpu_cap && mem + 5 <= self.mem_cap && psi < 200;

        if cpu_over {
            self.over_streak += 1;
        } else {
            self.over_streak = 0;
        }

        if total > 0 && (mem_over || self.over_streak >= 3) {
            let cut = (self.target / 4).max(1);
            self.target = self.target.saturating_sub(cut).max(1);
            self.throttled = true;
            self.over_streak = 0;
            self.calm_streak = 0;
        } else if calm {
            self.calm_streak += 1;
            if self.calm_streak >= 3 {
                self.calm_streak = 0;
                if self.target < total {
                    self.target += 1;
                }
            }
        } else {
            self.calm_streak = 0;
        }

        if self.target >= total {
            self.throttled = false;
        }

        GovOut {
            cpu_pct: cpu,
            mem_pct: mem,
            target: self.target,
            throttled: self.throttled as u32,
            psi_mem_x100: psi,
        }
    }
}

#[no_mangle]
pub extern "C" fn gov_new(cpu_cap: u32, mem_cap: u32) -> *mut Gov {
    Box::into_raw(Box::new(Gov::new(cpu_cap, mem_cap)))
}

#[no_mangle]
pub unsafe extern "C" fn gov_poll(g: *mut Gov, total: u32, out: *mut GovOut) {
    if g.is_null() || out.is_null() {
        return;
    }
    let gov = &mut *g;
    *out = gov.poll(total);
}

#[no_mangle]
pub unsafe extern "C" fn gov_free(g: *mut Gov) {
    if !g.is_null() {
        drop(Box::from_raw(g));
    }
}

// cpu percent comes from /proc/stat deltas, memory from MemAvailable so reclaimable page cache does not count as used
// cuts happen after 3 samples over the cpu cap or at once on memory, regrowth needs 3 calm samples per step
// the whole ffi surface is three functions, everything else stays safe rust
