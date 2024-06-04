use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_os = "macos")] {
        mod macos;
        pub use self::macos::*;
    } else {
        mod others;
        pub use self::others::*;
    }
}
