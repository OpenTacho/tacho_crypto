pub mod auth;
pub mod cert;
pub mod ec;
pub mod ecdh;
pub mod session;

#[macro_export]
macro_rules! ensure_eq {
    ($left:expr, $right:expr $(,)?) => {
        if $left != $right {
            Err(::eyre::eyre!(
                concat!(
                    "ensure_eq failed: `",
                    stringify!($left),
                    "` != `",
                    stringify!($right),
                    "`, {} != {}"
                ),
                $left,
                $right
            ))?
        }
    };
}
