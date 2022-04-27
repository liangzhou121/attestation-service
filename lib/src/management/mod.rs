use super::*;

pub mod opa;

#[derive(Debug)]
pub enum Files {
    Policy,
    Reference,
    NONE,
}

#[derive(Debug)]
pub struct PolicyEngineSetFile {
    pub engine: PolicyEngine,
    pub tee: TEEs,
    pub file: Files,
    pub content: String,
}

#[derive(Debug)]
pub struct PolicyEngineGetFile {
    pub engine: PolicyEngine,
    pub tee: TEEs,
    pub file: Files,
}

#[derive(Debug)]
pub struct OpaTest {
    pub policycontent: String,
    pub referencecontent: String,
    pub inputcontent: String,
}
