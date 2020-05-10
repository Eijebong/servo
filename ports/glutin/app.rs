/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Application entry point, runs the event loop.

use crate::browser::Browser;
use crate::embedder::EmbedderCallbacks;
use crate::events_loop::EventsLoop;
use crate::window_trait::WindowPortsMethods;
use crate::{headed_window, headless_window};
use winit::window::WindowId;
use servo::compositing::windowing::WindowEvent;
use servo::config::opts::{self, parse_url_or_filename};
use servo::servo_config::pref;
use servo::servo_url::ServoUrl;
use servo::{BrowserId, Servo};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::env;
use std::mem;
use std::rc::Rc;
use webxr::glwindow::GlWindowDiscovery;

thread_local! {
    pub static WINDOWS: RefCell<HashMap<WindowId, Rc<dyn WindowPortsMethods>>> = RefCell::new(HashMap::new());
}

pub struct App {
    servo: Option<Servo<dyn WindowPortsMethods>>,
    browser: RefCell<Browser<dyn WindowPortsMethods>>,
    event_queue: RefCell<Vec<WindowEvent>>,
    suspended: Cell<bool>,
}

impl App {
    pub fn run(
        no_native_titlebar: bool,
        device_pixels_per_px: Option<f32>,
        user_agent: Option<String>,
    ) {
        let events_loop = EventsLoop::new(opts::get().headless);

        // Implements window methods, used by compositor.
        let window = if opts::get().headless {
            headless_window::Window::new(opts::get().initial_window_size, device_pixels_per_px)
        } else {
            Rc::new(headed_window::Window::new(
                opts::get().initial_window_size,
                &events_loop,
                no_native_titlebar,
                device_pixels_per_px,
            ))
        };

        let xr_discovery = /*if pref!(dom.webxr.glwindow.enabled) {
            let window = window.clone();
            let surfman = window.webrender_surfman();
            let factory = Box::new(|| Ok(window.new_glwindow(&events_loop)));
            Some(GlWindowDiscovery::new(
                surfman.connection(),
                surfman.adapter(),
                surfman.context_attributes(),
                factory,
            ))
        } else {*/
            None;
        //};

        // Implements embedder methods, used by libservo and constellation.
        let embedder = Box::new(EmbedderCallbacks::new(
            events_loop.create_event_loop_waker(),
            xr_discovery,
        ));

        // Handle browser state.
        let browser = Browser::new(window.clone());

        let mut servo = Servo::new(embedder, window.clone(), user_agent);
        let browser_id = BrowserId::new();
        servo.handle_events(vec![WindowEvent::NewBrowser(get_default_url(), browser_id)]);
        servo.setup_logging();

        register_window(window);

        let app = App {
            event_queue: RefCell::new(vec![]),
            browser: RefCell::new(browser),
            servo: Some(servo),
            suspended: Cell::new(false),
        };

        app.run_loop(events_loop);
    }

    fn get_events(&self) -> Vec<WindowEvent> {
        mem::replace(&mut *self.event_queue.borrow_mut(), Vec::new())
    }

    // This function decides whether the event should be handled during `run_forever`.
    fn winit_event_to_servo_event(&self, event: winit::event::Event<()>) {
        match event {
            // App level events
            winit::event::Event::Suspended => {
                self.suspended.set(true);
            },
            winit::event::Event::Resumed => {
                self.suspended.set(false);
                self.event_queue.borrow_mut().push(WindowEvent::Idle);
            },
            // XXX: This was Awakened
            winit::event::Event::UserEvent(_) => {
                self.event_queue.borrow_mut().push(WindowEvent::Idle);
            },
            winit::event::Event::DeviceEvent { .. } => {},

            winit::event::Event::RedrawRequested(_) => {
                self.event_queue.borrow_mut().push(WindowEvent::Refresh);
            },

            // Window level events
            winit::event::Event::WindowEvent {
                window_id, event, ..
            } => {
                return WINDOWS.with(|windows| {
                    match windows.borrow().get(&window_id) {
                        None => {
                            warn!("Got an event from unknown window");
                        },
                        Some(window) => {
                            window.winit_event_to_servo_event(event);
                        },
                    }
                });
            },
            _ => {},
        }
    }

    fn run_loop(mut self, event_loop: EventsLoop) {
        event_loop.run_forever(move |e, control_flow| {
            // If self.servo is None here, it means that we're in the process of shutting down,
            // let's ignore events.
            if self.servo.is_none() {
                return;
            }

            // Handle the event
            self.winit_event_to_servo_event(e);

            let animating = WINDOWS.with(|windows| {
                windows
                    .borrow()
                    .iter()
                    .any(|(_, window)| window.is_animating())
            });

            // Block until the window gets an event
            if !animating || self.suspended.get() {
                *control_flow = winit::event_loop::ControlFlow::Wait;
            } else {
                *control_flow = winit::event_loop::ControlFlow::Poll;
            }

            let stop = self.handle_events();
            if stop {
                *control_flow = winit::event_loop::ControlFlow::Exit;
                self.servo.take().unwrap().deinit();
            }

        });
    }

    fn handle_events(&mut self) -> bool {
        let mut browser = self.browser.borrow_mut();

        // FIXME:
        // As of now, we support only one browser (self.browser)
        // but have multiple windows (dom.webxr.glwindow). We forward
        // the events of all the windows combined to that single
        // browser instance. Pressing the "a" key on the glwindow
        // will send a key event to the servo window.

        let mut app_events = self.get_events();
        WINDOWS.with(|windows| {
            for (_win_id, window) in &*windows.borrow() {
                app_events.extend(window.get_events());
            }
        });

        // FIXME: this could be handled by Servo. We don't need
        // a repaint_synchronously function exposed.
        let need_resize = app_events.iter().any(|e| match *e {
            WindowEvent::Resize => true,
            _ => false,
        });

        browser.handle_window_events(app_events);

        let mut servo_events = self.servo.as_mut().unwrap().get_events();
        loop {
            browser.handle_servo_events(servo_events);
            self.servo.as_mut().unwrap().handle_events(browser.get_events());
            if browser.shutdown_requested() {
                return true;
            }
            servo_events = self.servo.as_mut().unwrap().get_events();
            if servo_events.is_empty() {
                break;
            }
        }

        if need_resize {
            self.servo.as_mut().unwrap().repaint_synchronously();
        }
        false
    }
}

fn get_default_url() -> ServoUrl {
    // If the url is not provided, we fallback to the homepage in prefs,
    // or a blank page in case the homepage is not set either.
    let cwd = env::current_dir().unwrap();
    let cmdline_url = opts::get().url.clone();
    let pref_url = {
        let homepage_url = pref!(shell.homepage);
        parse_url_or_filename(&cwd, &homepage_url).ok()
    };
    let blank_url = ServoUrl::parse("about:blank").ok();

    cmdline_url.or(pref_url).or(blank_url).unwrap()
}

pub fn register_window(window: Rc<dyn WindowPortsMethods>) {
    WINDOWS.with(|w| {
        w.borrow_mut().insert(window.id(), window);
    });
}
