use std::sync::Arc;

use crate::core::config::Config;
use crate::core::simulation::Simulation;

pub struct Runner {
    pub simulations: Vec<Box<dyn Simulation>>,
    pub config: Arc<Config>,
}

impl Runner {
    pub fn new(config: Config) -> Self {
        Self {
            simulations: vec![],
            config: Arc::new(config),
        }
    }

    pub fn register(&mut self, sim: Box<dyn Simulation>) {
        self.simulations.push(sim);
    }
}
