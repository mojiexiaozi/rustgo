#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayEvent {
    Show,
    Connect,
    Disconnect,
    Quit,
}

#[derive(Default)]
pub struct WindowLifecycle {
    pub quitting: bool,
}

impl WindowLifecycle {
    pub fn update(
        &mut self,
        ctx: &eframe::egui::Context,
        tray_available: bool,
        event: Option<TrayEvent>,
    ) {
        use eframe::egui::ViewportCommand as Command;
        match event {
            Some(TrayEvent::Quit) => self.quitting = true,
            Some(TrayEvent::Show) if !self.quitting => {
                ctx.send_viewport_cmd(Command::Visible(true));
                ctx.send_viewport_cmd(Command::Minimized(false));
                ctx.send_viewport_cmd(Command::Focus);
            }
            _ => {}
        }
        if self.quitting {
            ctx.send_viewport_cmd(Command::Close);
        } else if tray_available && ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(Command::CancelClose);
            ctx.send_viewport_cmd(Command::Visible(false));
        }
    }
}

#[cfg(windows)]
pub fn decode_menu_id(id: u32) -> Option<TrayEvent> {
    match id {
        1 => Some(TrayEvent::Show),
        2 => Some(TrayEvent::Connect),
        3 => Some(TrayEvent::Disconnect),
        4 => Some(TrayEvent::Quit),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commands(
        lifecycle: &mut WindowLifecycle,
        tray: bool,
        event: Option<TrayEvent>,
        close: bool,
    ) -> Vec<eframe::egui::ViewportCommand> {
        let ctx = eframe::egui::Context::default();
        let mut input = eframe::egui::RawInput::default();
        if close {
            input
                .viewports
                .get_mut(&eframe::egui::ViewportId::ROOT)
                .unwrap()
                .events
                .push(eframe::egui::ViewportEvent::Close);
        }
        let mut output = ctx.run_ui(input, |ui| lifecycle.update(ui.ctx(), tray, event));
        output.textures_delta.clear();
        output.viewport_output[&eframe::egui::ViewportId::ROOT]
            .commands
            .clone()
    }

    #[test]
    fn close_hides_but_quit_exits_and_show_restores() {
        use eframe::egui::ViewportCommand as Command;
        let mut lifecycle = WindowLifecycle::default();
        let close = commands(&mut lifecycle, true, None, true);
        assert!(close.contains(&Command::CancelClose));
        assert!(close.contains(&Command::Visible(false)));
        let show = commands(&mut lifecycle, true, Some(TrayEvent::Show), false);
        assert!(show.contains(&Command::Visible(true)));
        assert!(show.contains(&Command::Minimized(false)));
        assert!(show.contains(&Command::Focus));
        let quit = commands(&mut lifecycle, true, Some(TrayEvent::Quit), true);
        assert!(quit.contains(&Command::Close));
        assert!(!quit.contains(&Command::CancelClose));
        assert!(lifecycle.quitting);
    }

    #[test]
    fn missing_tray_does_not_trap_window() {
        let result = commands(&mut WindowLifecycle::default(), false, None, true);
        assert!(!result.contains(&eframe::egui::ViewportCommand::CancelClose));
        assert!(!result.contains(&eframe::egui::ViewportCommand::Visible(false)));
    }

    #[test]
    fn hidden_window_accepts_restore_and_quit_without_painting() {
        use eframe::egui::{Context, RawInput, ViewportCommand as Command, ViewportId};
        let ctx = Context::default();
        let mut lifecycle = WindowLifecycle::default();
        let mut input = RawInput::default();
        input
            .viewports
            .get_mut(&ViewportId::ROOT)
            .unwrap()
            .minimized = Some(true);
        let show = ctx.run_logic(&input, |ctx| {
            lifecycle.update(ctx, true, Some(TrayEvent::Show));
        });
        assert!(show.viewport_commands[&ViewportId::ROOT].contains(&Command::Visible(true)));
        let quit = ctx.run_logic(&input, |ctx| {
            lifecycle.update(ctx, true, Some(TrayEvent::Quit));
        });
        assert!(quit.viewport_commands[&ViewportId::ROOT].contains(&Command::Close));
        assert!(!quit.viewport_commands[&ViewportId::ROOT].contains(&Command::CancelClose));
    }

    #[test]
    #[cfg(windows)]
    fn test_decode_valid_menu_ids() {
        assert_eq!(decode_menu_id(1), Some(TrayEvent::Show));
        assert_eq!(decode_menu_id(2), Some(TrayEvent::Connect));
        assert_eq!(decode_menu_id(3), Some(TrayEvent::Disconnect));
        assert_eq!(decode_menu_id(4), Some(TrayEvent::Quit));
    }

    #[test]
    #[cfg(windows)]
    fn test_decode_invalid_menu_id() {
        assert_eq!(decode_menu_id(0), None);
        assert_eq!(decode_menu_id(5), None);
        assert_eq!(decode_menu_id(999), None);
    }

    #[test]
    fn test_event_equality() {
        assert_eq!(TrayEvent::Show, TrayEvent::Show);
        assert_ne!(TrayEvent::Show, TrayEvent::Quit);
    }
}
