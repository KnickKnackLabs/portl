use std::collections::HashSet;

use portl_agent::RevocationSet;
use portl_agent::pipeline::{AcceptanceInput, AcceptanceOutcome, RateLimitGate, evaluate_offer};
use portl_core::id::Identity;
use portl_core::ticket::hash::{parent_ticket_id, ticket_id};
use portl_core::ticket::mint::{mint_delegated, mint_root};
use portl_core::ticket::offer::compute_pop_sig;
use portl_core::ticket::schema::{Capabilities, Delegation, MetaCaps, PortlBody, PortlTicket};
use portl_core::ticket::sign::sign_body;
use portl_core::ticket::verify::{MAX_DELEGATION_DEPTH, TrustRoots};
use portl_proto::ticket_v1::{AckReason, TicketOffer};
use tempfile::tempdir;

const NOW: u64 = 1_735_689_600;
const SOURCE_ID: [u8; 32] = [7; 32];

struct AllowAll;

impl RateLimitGate for AllowAll {
    fn check(&self, _source_id: [u8; 32]) -> bool {
        true
    }
}

struct DenyAll;

impl RateLimitGate for DenyAll {
    fn check(&self, _source_id: [u8; 32]) -> bool {
        false
    }
}

#[test]
fn accepts_valid_root_ticket() {
    let fixture = Fixture::new();
    let ticket = fixture.root_ticket(meta_caps(true, true), NOW, NOW + 300, None);

    let outcome = fixture.evaluate(&offer(&ticket, &[], None), &AllowAll);

    match outcome {
        AcceptanceOutcome::Accepted {
            caps,
            ticket_id: id,
            ..
        } => {
            assert_eq!(*caps, meta_caps(true, true));
            assert_eq!(id, ticket_id(&ticket.sig));
        }
        AcceptanceOutcome::Rejected { reason } => panic!("unexpected rejection: {reason:?}"),
    }
}

#[test]
fn rejects_bad_signature() {
    let fixture = Fixture::new();
    let mut ticket = fixture.root_ticket(meta_caps(true, true), NOW, NOW + 300, None);
    ticket.body.not_after += 1;

    let outcome = fixture.evaluate(&offer(&ticket, &[], None), &AllowAll);

    assert_rejected(outcome, &AckReason::BadSignature);
}

#[test]
fn rejects_malformed_postcard() {
    let fixture = Fixture::new();
    let outcome = fixture.evaluate(
        &raw_offer(vec![1, 2, 3], Vec::new(), None, [3; 16]),
        &AllowAll,
    );

    assert_rejected(
        outcome,
        &AckReason::InternalError {
            detail: Some("malformed offer".to_owned()),
        },
    );
}

#[test]
fn rejects_non_canonical_ticket() {
    let fixture = Fixture::new();
    let mut ticket = fixture.root_ticket(meta_caps(true, true), NOW, NOW + 300, None);
    ticket.body.caps.presence = 0;

    let outcome = fixture.evaluate(
        &raw_offer(
            postcard::to_stdvec(&ticket).expect("encode non-canonical ticket"),
            Vec::new(),
            None,
            [3; 16],
        ),
        &AllowAll,
    );

    assert_rejected(
        outcome,
        &AckReason::InternalError {
            detail: Some("non-canonical ticket".to_owned()),
        },
    );
}

#[test]
fn rejects_bad_chain() {
    let fixture = Fixture::new();
    let root = fixture.root_ticket(meta_caps(true, true), NOW, NOW + 300, None);
    let child = mint_delegated(
        fixture.operator.signing_key(),
        &root,
        meta_caps(true, false),
        NOW,
        NOW + 300,
        None,
    )
    .expect("mint child");

    let outcome = fixture.evaluate(&offer(&child, &[], None), &AllowAll);

    assert_rejected(outcome, &AckReason::BadChain);
}

#[test]
fn rejects_caps_exceed_parent() {
    let fixture = Fixture::new();
    let root = fixture.root_ticket(meta_caps(true, false), NOW, NOW + 300, None);
    let child_body = PortlBody {
        caps: meta_caps(true, true),
        target: root.body.target,
        alpns_extra: vec![],
        not_before: NOW,
        not_after: NOW + 300,
        issuer: Some(fixture.operator.verifying_key()),
        parent: Some(Delegation {
            parent_ticket_id: parent_ticket_id(&root.sig),
            depth_remaining: MAX_DELEGATION_DEPTH - 1,
        }),
        nonce: [1; 8],
        bearer: None,
        to: None,
    };
    let child = PortlTicket {
        v: 1,
        addr: root.addr.clone(),
        sig: sign_body(fixture.operator.signing_key(), &child_body).expect("sign child"),
        body: child_body,
    };

    let outcome = fixture.evaluate(&offer(&child, &[root], None), &AllowAll);

    assert_rejected(outcome, &AckReason::CapsExceedParent);
}

#[test]
fn rejects_not_yet_valid_ticket() {
    let fixture = Fixture::new();
    let ticket = fixture.root_ticket(meta_caps(true, true), NOW + 61, NOW + 300, None);

    let outcome = fixture.evaluate(&offer(&ticket, &[], None), &AllowAll);

    assert_rejected(outcome, &AckReason::NotYetValid);
}

#[test]
fn rejects_expired_ticket() {
    let fixture = Fixture::new();
    let ticket = fixture.root_ticket(meta_caps(true, true), NOW - 120, NOW, None);

    let outcome = fixture.evaluate(&offer(&ticket, &[], None), &AllowAll);

    assert_rejected(outcome, &AckReason::Expired);
}

#[test]
fn rejects_revoked_ticket() {
    let fixture = Fixture::new();
    let ticket = fixture.root_ticket(meta_caps(true, true), NOW, NOW + 300, None);
    let revocations = fixture.revocations_with(ticket_id(&ticket.sig));

    let outcome =
        fixture.evaluate_with_revocations(&offer(&ticket, &[], None), &AllowAll, &revocations);

    assert_rejected(outcome, &AckReason::Revoked);
}

#[test]
fn rejects_missing_proof_for_bound_ticket() {
    let fixture = Fixture::new();
    let holder = Identity::new();
    let ticket = fixture.root_ticket(
        meta_caps(true, true),
        NOW,
        NOW + 300,
        Some(holder.verifying_key()),
    );

    let outcome = fixture.evaluate(&offer(&ticket, &[], None), &AllowAll);

    assert_rejected(outcome, &AckReason::ProofMissing);
}

#[test]
fn rejects_invalid_proof() {
    let fixture = Fixture::new();
    let holder = Identity::new();
    let other = Identity::new();
    let ticket = fixture.root_ticket(
        meta_caps(true, true),
        NOW,
        NOW + 300,
        Some(holder.verifying_key()),
    );
    let proof = compute_pop_sig(other.signing_key(), &ticket_id(&ticket.sig), &[3; 16]);

    let outcome = fixture.evaluate(
        &offer_with_nonce(&ticket, &[], Some(proof), [3; 16]),
        &AllowAll,
    );

    assert_rejected(outcome, &AckReason::ProofInvalid);
}

#[test]
fn rejects_rate_limited_source() {
    let fixture = Fixture::new();
    let ticket = fixture.root_ticket(meta_caps(true, true), NOW, NOW + 300, None);

    let outcome = fixture.evaluate(&offer(&ticket, &[], None), &DenyAll);

    assert_rejected(outcome, &AckReason::RateLimited);
}

#[test]
fn listener_mode_rejects_master_ticket() {
    let fixture = Fixture::new();
    let ticket = fixture.master_root_ticket(b"slicer-token".to_vec());

    let outcome = fixture.evaluate_in_mode(
        &offer(&ticket, &[], None),
        &AllowAll,
        &portl_agent::AgentMode::Listener,
    );

    assert_rejected(
        outcome,
        &AckReason::InternalError {
            detail: Some("listener mode refuses master tickets".to_owned()),
        },
    );
}

#[test]
fn gateway_mode_rejects_non_master_ticket() {
    let fixture = Fixture::new();
    let ticket = fixture.root_ticket(meta_caps(true, true), NOW, NOW + 300, None);

    let outcome = fixture.evaluate_in_mode(&offer(&ticket, &[], None), &AllowAll, &gateway_mode());

    assert_rejected(
        outcome,
        &AckReason::InternalError {
            detail: Some("gateway mode requires a master ticket".to_owned()),
        },
    );
}

#[test]
fn gateway_mode_accepts_master_ticket() {
    let fixture = Fixture::new();
    let ticket = fixture.master_root_ticket(b"slicer-token".to_vec());

    let outcome = fixture.evaluate_in_mode(&offer(&ticket, &[], None), &AllowAll, &gateway_mode());

    match outcome {
        AcceptanceOutcome::Accepted { bearer, .. } => {
            assert_eq!(bearer.as_deref(), Some(b"slicer-token".as_ref()));
        }
        AcceptanceOutcome::Rejected { reason } => panic!("unexpected rejection: {reason:?}"),
    }
}

fn gateway_mode() -> portl_agent::AgentMode {
    portl_agent::AgentMode::Gateway {
        upstream_url: "http://slicer.test:8080".to_owned(),
        upstream_host: "slicer.test".to_owned(),
        upstream_port: 8080,
    }
}

fn assert_rejected(outcome: AcceptanceOutcome, expected: &AckReason) {
    match outcome {
        AcceptanceOutcome::Accepted { .. } => panic!("expected rejection"),
        AcceptanceOutcome::Rejected { reason } => assert_eq!(&reason, expected),
    }
}

fn meta_caps(ping: bool, info: bool) -> Capabilities {
    Capabilities {
        presence: 0b0010_0000,
        shell: None,
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: Some(MetaCaps { ping, info }),
    }
}

fn offer(ticket: &PortlTicket, chain: &[PortlTicket], proof: Option<[u8; 64]>) -> TicketOffer {
    offer_with_nonce(ticket, chain, proof, [3; 16])
}

fn offer_with_nonce(
    ticket: &PortlTicket,
    chain: &[PortlTicket],
    proof: Option<[u8; 64]>,
    client_nonce: [u8; 16],
) -> TicketOffer {
    raw_offer(
        portl_core::ticket::encode(ticket).expect("encode ticket"),
        chain
            .iter()
            .map(|ticket| portl_core::ticket::encode(ticket).expect("encode chain ticket"))
            .collect(),
        proof,
        client_nonce,
    )
}

fn raw_offer(
    ticket: Vec<u8>,
    chain: Vec<Vec<u8>>,
    proof: Option<[u8; 64]>,
    client_nonce: [u8; 16],
) -> TicketOffer {
    TicketOffer {
        ticket,
        chain,
        proof,
        client_nonce,
    }
}

struct Fixture {
    operator: Identity,
    target: Identity,
    trust_roots: TrustRoots,
    tempdir: tempfile::TempDir,
    revocations: RevocationSet,
}

impl Fixture {
    fn new() -> Self {
        let operator = Identity::new();
        let target = Identity::new();
        let trust_roots = TrustRoots(HashSet::from([operator.verifying_key()]));
        let tempdir = tempdir().expect("tempdir");
        let revocations =
            RevocationSet::load(tempdir.path().join("revocations.json")).expect("load revocations");

        Self {
            operator,
            target,
            trust_roots,
            tempdir,
            revocations,
        }
    }

    fn root_ticket(
        &self,
        caps: Capabilities,
        not_before: u64,
        not_after: u64,
        to: Option<[u8; 32]>,
    ) -> PortlTicket {
        mint_root(
            self.operator.signing_key(),
            iroh_base::EndpointAddr::new(self.target.endpoint_id()),
            caps,
            not_before,
            not_after,
            to,
        )
        .expect("mint root")
    }

    fn revocations_with(&self, id: [u8; 16]) -> RevocationSet {
        let path = self.tempdir.path().join("custom-revocations.json");
        let mut revocations = RevocationSet::load(path).expect("load custom revocations");
        revocations.insert(id);
        revocations
    }

    fn master_root_ticket(&self, bearer: Vec<u8>) -> PortlTicket {
        let mut ticket = self.root_ticket(tcp_caps_to_upstream(), NOW, NOW + 300, None);
        ticket.body.bearer = Some(bearer);
        ticket.sig =
            sign_body(self.operator.signing_key(), &ticket.body).expect("sign master root body");
        ticket
    }

    fn evaluate(&self, offer: &TicketOffer, rate_limit: &dyn RateLimitGate) -> AcceptanceOutcome {
        self.evaluate_with_revocations(offer, rate_limit, &self.revocations)
    }

    fn evaluate_in_mode(
        &self,
        offer: &TicketOffer,
        rate_limit: &dyn RateLimitGate,
        mode: &portl_agent::AgentMode,
    ) -> AcceptanceOutcome {
        evaluate_offer(&AcceptanceInput {
            offer,
            source_id: SOURCE_ID,
            trust_roots: &self.trust_roots,
            revocations: &self.revocations,
            now: NOW,
            rate_limit,
            mode,
        })
    }

    fn evaluate_with_revocations(
        &self,
        offer: &TicketOffer,
        rate_limit: &dyn RateLimitGate,
        revocations: &RevocationSet,
    ) -> AcceptanceOutcome {
        evaluate_offer(&AcceptanceInput {
            offer,
            source_id: SOURCE_ID,
            trust_roots: &self.trust_roots,
            revocations,
            now: NOW,
            rate_limit,
            mode: &portl_agent::AgentMode::Listener,
        })
    }
}

fn tcp_caps_to_upstream() -> Capabilities {
    use portl_core::ticket::schema::PortRule;
    Capabilities {
        presence: 0b0000_0010,
        shell: None,
        tcp: Some(vec![PortRule {
            host_glob: "slicer.test".to_owned(),
            port_min: 8080,
            port_max: 8080,
        }]),
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}
