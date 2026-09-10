use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, EventLoop};
use winit::window::{Window, WindowId};

#[derive(Default)]
struct PressureTracker {
    window: Option<Window>,
}

impl ApplicationHandler for PressureTracker {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        let attributes = Window::default_attributes().with_title("Mac Force Touch Tracker");
        let window = event_loop
            .create_window(attributes)
            .expect("failed to create window");
        window.focus_window();

        self.window = Some(window);
        println!("Press hard on the trackpad while the cursor is over the window.");
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) {
        if self.window.as_ref().is_none_or(|w| w.id() != window_id) {
            return;
        }

        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::TouchpadPressure {
                pressure, stage, ..
            } => {
                println!("pressure: {pressure:.3}  stage: {stage}");
            }
            _ => {}
        }
    }
}

fn main() {
    let event_loop = EventLoop::new().expect("failed to create event loop");
    event_loop
        .run_app(&mut PressureTracker::default())
        .expect("event loop failed");
}
