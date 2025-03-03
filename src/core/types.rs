#[derive(Debug)]
pub struct WindowInfo {
    pub app_class: String,
    pub title: String,
}


impl WindowInfo {
    pub fn new(app_class: String, title: String) -> Self {
        Self { app_class, title }
    }
}

