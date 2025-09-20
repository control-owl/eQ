use sysinfo::{RefreshKind, System};

pub fn get_free_memory_size() -> usize {
  let mut system = System::new_with_specifics(RefreshKind::everything().without_memory());
  system.refresh_memory();

  let available_memory = system.available_memory(); // in bytes
  const BYTES_PER_ROW: u64 = 450; // estimated, ????

  if available_memory > 0 {
    ((available_memory as f64 * 0.8) / BYTES_PER_ROW as f64) as usize
  } else {
    // TODO: get total active coins number
    260 // Minimum fallback
  }
}