use anyhow::Result;
use std::sync::Arc;

use crate::core::config::Config;
use crate::core::logger;
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

    /// Runs all registered simulations in sequence.
    /// Uses the Neo-Offensive styled logger for clean output.
    pub fn run_all(&self) -> Result<()> {
        for sim in &self.simulations {
            // Styled module header
            logger::module_start(sim.name());

            // Run simulation
            sim.run(&self.config)?;
        }

        Ok(())
    }
}
