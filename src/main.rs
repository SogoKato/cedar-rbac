use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use itertools::Itertools;
use clap::Parser;
use cedar_policy::{
    Authorizer, Context, Decision, Diagnostics, Entities, Entity, EntityId, EntityTypeName, EntityUid, ParseErrors, PolicySet, Request,
    Schema, SchemaError, ValidationMode, Validator,
};
use thiserror::Error;

/// Sample rbac implementation with cedar
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Principal
    #[arg()]
    principal: String,

    /// Action
    #[arg()]
    action: String,

    /// Resource: subject of info.
    #[arg()]
    resource: String,
}

struct User {
    id: String,
    role: String,
}

impl From<User> for Entity {
    fn from(value: User) -> Self {
        let eid = EntityId::from_str(&value.id).unwrap();
        let type_name = EntityTypeName::from_str("Kubernetes::User").unwrap();
        let euid = EntityUid::from_type_name_and_id(type_name, eid);
        let attrs = HashMap::new();
        let parent_eid = EntityId::from_str(&value.role).unwrap();
        let parent_type_name = EntityTypeName::from_str("Kubernetes::Role").unwrap();
        let parent_euid = EntityUid::from_type_name_and_id(parent_type_name, parent_eid);
        let parents = HashSet::from([parent_euid]);
        Entity::new(euid, attrs, parents)
    }
}

struct Role {
    id: String,
}

impl From<Role> for Entity {
    fn from(value: Role) -> Self {
        let eid = EntityId::from_str(&value.id).unwrap();
        let type_name = EntityTypeName::from_str("Kubernetes::Role").unwrap();
        let euid = EntityUid::from_type_name_and_id(type_name, eid);
        let attrs = HashMap::new();
        let parents = HashSet::new();
        Entity::new(euid, attrs, parents)
    }
}

struct Pod {
    id: String,
}

impl From<Pod> for Entity {
    fn from(value: Pod) -> Self {
        let eid = EntityId::from_str(&value.id).unwrap();
        let type_name = EntityTypeName::from_str("Kubernetes::Info").unwrap();
        let euid = EntityUid::from_type_name_and_id(type_name, eid);
        let attrs = HashMap::new();
        let parents = HashSet::new();
        Entity::new(euid, attrs, parents)
    }
}

fn main() {
    let args = Args::parse();

    let principal = find_user_by_id(&args.principal).unwrap();
    let resource = find_pod_by_id(&args.resource).unwrap();

    match is_authorized(&principal.into(), &args.action, &resource.into()) {
        Ok(_) => println!("Hello {}! You can {} {}.", args.principal, &args.action, &args.resource),
        Err(e) => println!("{}", e),
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("No Such Record: {0}")]
    NoSuchRecord(String),
    #[error("No Such Entity: {0}")]
    NoSuchEntity(EntityUid),
    #[error("Authorization Denied")]
    AuthDenied(Diagnostics),
    #[error("The list {0} does not contain a task with id {1}")]
    InvalidTaskId(EntityUid, i64),
    #[error("Internal Error")]
    Type,
    #[error("Internal Error")]
    IO(#[from] std::io::Error),
    #[error("Error Parsing PolicySet: {0}")]
    Policy(#[from] ParseErrors),
    #[error("Error constructing authorization request: {0}")]
    Request(String),
    #[error("Error Parsing Schema: {0}")]
    Schema(#[from] SchemaError),
    #[error("Validation Failed: {0}")]
    Validation(String),
}

fn find_user_by_id(id: &str) -> std::result::Result<User, Error> {
    match id {
        "Alice" => {
            Ok(User { id: "Alice".to_string(), role: "admin".to_string() })
        }
        "Bob" => {
            Ok(User { id: "Bob".to_string(), role: "viewer".to_string() })
        }
        _ => {
            Err(Error::NoSuchRecord(id.to_string()))
        }
    }
}

fn find_pod_by_id(id: &str) -> std::result::Result<Pod, Error> {
    if id == "nginx-pod" {
        Ok(Pod { id: "nginx-pod".to_string() })
    } else {
        Err(Error::NoSuchRecord(id.to_string()))
    }
}

fn is_authorized(principal: &Entity, action: &str, resource: &Entity) -> std::result::Result<(), Error> {
    let authorizer = Authorizer::new();
    let schema = get_schema()?;
    let policies = get_policy_set(&schema)?;
    let entities = get_entity_set();
    let action_uid: EntityUid = format!(r#"Kubernetes::Action::"{action}""#).parse().unwrap();
    let q = Request::new(
        principal.uid().into(),
        action_uid.into(),
        resource.uid().into(),
        Context::empty(),
    );
    let response = authorizer.is_authorized(&q, &policies, &entities);
    match response.decision() {
        Decision::Allow => Ok(()),
        Decision::Deny => Err(Error::AuthDenied(response.diagnostics().clone())),
    }
}

fn get_schema() -> std::result::Result<Schema, Error> {
    let schema_path = "k8s.cedarschema.json";
    let schema_file = std::fs::File::open(&schema_path)?;
    Ok(Schema::from_file(schema_file)?)
}

fn get_policy_set(schema: &Schema) -> std::result::Result<PolicySet, Error> {
    let policies_path = "policies.cedar";

    let policy_src = std::fs::read_to_string(&policies_path)?;
    let policies = policy_src.parse()?;
    let validator = Validator::new(schema.clone());
    let output = validator.validate(&policies, ValidationMode::default());

    if output.validation_passed() {
        Ok(policies)
    } else {
        let error_string = output
            .validation_errors()
            .map(|err| format!("{err}"))
            .join("\n");
        Err(Error::Validation(error_string))
    }
}

fn get_entity_set() -> Entities {
    let users = vec![
        Entity::from(User { id: "Alice".to_string(), role: "admin".to_string() }),
        Entity::from(User { id: "Bob".to_string(), role: "viewer".to_string() }),
    ];
    let roles = vec![
        Entity::from(Role { id: "admin".to_string() }),
    ];
    let resources = vec![
        Entity::from(Pod { id: "nginx".to_string() }),
    ];
    let all = [users, roles, resources].concat();
    Entities::from_entities(all).unwrap()
}
