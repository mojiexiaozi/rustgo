#![forbid(unsafe_code)]
#![allow(dead_code)]

use crate::state::p2p::{P2PViewModel, PathRowKind};
use crate::ui::formatting::format_age_millis;
use eframe::egui::Ui;

pub struct P2PPanel;

impl P2PPanel {
    pub fn new() -> Self {
        Self
    }

    pub fn show(&mut self, ui: &mut Ui, vm: &P2PViewModel, now_millis: u64) {
        ui.heading("P2P Paths");
        ui.separator();

        let rows = vm.rows(now_millis);
        if rows.is_empty() {
            ui.label("No active P2P exports");
            return;
        }

        eframe::egui::Grid::new("p2p_grid")
            .striped(true)
            .show(ui, |ui| {
                ui.label("Export");
                ui.label("Path");
                ui.label("Age");
                ui.end_row();

                for row in rows {
                    ui.monospace(&row.export_name);

                    match &row.kind {
                        PathRowKind::Direct { address } => {
                            ui.colored_label(
                                eframe::egui::Color32::GREEN,
                                format!("Direct ({})", address),
                            );
                        }
                        PathRowKind::Relay => {
                            ui.colored_label(eframe::egui::Color32::YELLOW, "Relay");
                        }
                    }

                    ui.label(format_age_millis(now_millis, now_millis - row.age_millis));
                    ui.end_row();
                }
            });
    }
}

impl Default for P2PPanel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustgoc::{PathKindStatus, PathStatus, PathStatusStore};

    #[test]
    fn test_empty_exports() {
        let store = PathStatusStore::new();
        let vm = P2PViewModel::new(store);
        let rows = vm.rows(1000);
        assert_eq!(rows.len(), 0);
    }

    #[test]
    fn test_direct_and_relay_rows() {
        let store = PathStatusStore::new();
        store.record(
            "export1".to_string(),
            PathStatus {
                kind: PathKindStatus::Direct {
                    address: "10.0.0.5:7000".to_string(),
                },
                updated_unix_millis: 1000,
            },
        );
        store.record(
            "export2".to_string(),
            PathStatus {
                kind: PathKindStatus::Relay,
                updated_unix_millis: 2000,
            },
        );

        let mut vm = P2PViewModel::new(store);
        vm.update();
        let rows = vm.rows(3000);

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].export_name, "export1");
        match &rows[0].kind {
            PathRowKind::Direct { address } => assert_eq!(address, "10.0.0.5:7000"),
            _ => panic!("Expected Direct"),
        }
        assert_eq!(rows[0].age_millis, 2000);

        assert_eq!(rows[1].export_name, "export2");
        assert!(matches!(rows[1].kind, PathRowKind::Relay));
        assert_eq!(rows[1].age_millis, 1000);
    }
}
