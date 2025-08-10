#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_time::Timer;
use esp_backtrace as _;
use esp_hal::{
    self,
    clock::CpuClock,
    gpio::{Level, Output},
    timer::timg::TimerGroup,
};
use esp_hal_embassy::main;
use esp_println::println;

// Linked-List First Fit Heap allocator (feature = "llff")
use embedded_alloc::LlffHeap as Heap;

extern crate alloc;

#[global_allocator]
static HEAP: Heap = Heap::empty();

#[main]
async fn main(_spawner: Spawner) {
    esp_println::logger::init_logger_from_env();

    let mut config = esp_hal::Config::default();
    config.cpu_clock = CpuClock::max();
    let peripherals = esp_hal::init(config);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_hal_embassy::init(timg0.timer0);

    let mut led = Output::new(peripherals.GPIO17, Level::High);
    loop {
        println!("Hello, World!");

        {
            // just a compile test for tachograph API
            let ca_cert_bytes = include_bytes!("ERCA Gen2 (1) Root Certificate.bin");
            let ca_cert_raw = TachographCertificateRaw::from_bytes(ca_cert_bytes).unwrap();
            let ca_cert = TachographCertificate::from_raw(&ca_cert_raw).unwrap();

            ca_cert.verify_with(ca_cert).unwrap();
        }

        led.toggle();
        Timer::after_millis(1_000).await;
    }
}
