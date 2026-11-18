PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS graph_snapshots (
    id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('building', 'complete')),
    created_at TEXT NOT NULL,
    UNIQUE (repository_id, commit_sha, parser_version)
);
CREATE TABLE IF NOT EXISTS graph_nodes (
    snapshot_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    source_path TEXT NOT NULL,
    source_line INTEGER NOT NULL CHECK (source_line > 0),
    commit_sha TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, node_id),
    FOREIGN KEY (snapshot_id) REFERENCES graph_snapshots(id)
);
CREATE TABLE IF NOT EXISTS graph_edges (
    snapshot_id TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    source_node TEXT NOT NULL,
    target_node TEXT NOT NULL,
    relation TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    evidence_status TEXT NOT NULL CHECK (evidence_status IN ('observed', 'inferred', 'hypothesized', 'verified', 'refuted')),
    source_path TEXT NOT NULL,
    source_line INTEGER NOT NULL CHECK (source_line > 0),
    commit_sha TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, edge_id),
    FOREIGN KEY (snapshot_id, source_node) REFERENCES graph_nodes(snapshot_id, node_id),
    FOREIGN KEY (snapshot_id, target_node) REFERENCES graph_nodes(snapshot_id, node_id)
);
CREATE TABLE IF NOT EXISTS graph_evidence (
    snapshot_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    source_path TEXT NOT NULL,
    source_line INTEGER NOT NULL CHECK (source_line > 0),
    commit_sha TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, evidence_id),
    FOREIGN KEY (snapshot_id) REFERENCES graph_snapshots(id)
);
CREATE TABLE IF NOT EXISTS graph_node_evidence (
    snapshot_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, node_id, evidence_id),
    FOREIGN KEY (snapshot_id, node_id) REFERENCES graph_nodes(snapshot_id, node_id),
    FOREIGN KEY (snapshot_id, evidence_id) REFERENCES graph_evidence(snapshot_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS graph_edge_evidence (
    snapshot_id TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, edge_id, evidence_id),
    FOREIGN KEY (snapshot_id, edge_id) REFERENCES graph_edges(snapshot_id, edge_id),
    FOREIGN KEY (snapshot_id, evidence_id) REFERENCES graph_evidence(snapshot_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS graph_hypotheses (
    snapshot_id TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, hypothesis_id),
    FOREIGN KEY (snapshot_id) REFERENCES graph_snapshots(id)
);
CREATE TABLE IF NOT EXISTS graph_paths (
    snapshot_id TEXT NOT NULL,
    path_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, path_id),
    FOREIGN KEY (snapshot_id) REFERENCES graph_snapshots(id)
);
CREATE TABLE IF NOT EXISTS graph_validations (
    snapshot_id TEXT NOT NULL,
    validation_id TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, validation_id),
    FOREIGN KEY (snapshot_id, hypothesis_id) REFERENCES graph_hypotheses(snapshot_id, hypothesis_id)
);
CREATE TABLE IF NOT EXISTS graph_remediations (
    snapshot_id TEXT NOT NULL,
    remediation_id TEXT NOT NULL,
    validation_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, remediation_id),
    FOREIGN KEY (snapshot_id, validation_id) REFERENCES graph_validations(snapshot_id, validation_id)
);
CREATE INDEX IF NOT EXISTS graph_edges_from_idx ON graph_edges(snapshot_id, source_node);
CREATE INDEX IF NOT EXISTS graph_edges_to_idx ON graph_edges(snapshot_id, target_node);
CREATE INDEX IF NOT EXISTS graph_snapshots_repo_idx ON graph_snapshots(repository_id, created_at);
CREATE TRIGGER IF NOT EXISTS graph_snapshots_no_delete BEFORE DELETE ON graph_snapshots
BEGIN SELECT RAISE(ABORT, 'immutable snapshot'); END;
DROP TRIGGER IF EXISTS graph_snapshots_one_transition;
CREATE TRIGGER graph_snapshots_one_transition BEFORE UPDATE ON graph_snapshots
WHEN OLD.status <> 'building' OR NEW.status <> 'complete' OR OLD.id <> NEW.id
 OR OLD.repository_id <> NEW.repository_id OR OLD.commit_sha <> NEW.commit_sha
 OR OLD.parser_version <> NEW.parser_version OR OLD.content_sha256 <> NEW.content_sha256
 OR OLD.created_at <> NEW.created_at
BEGIN SELECT RAISE(ABORT, 'immutable snapshot'); END;
CREATE TRIGGER IF NOT EXISTS graph_nodes_no_update BEFORE UPDATE ON graph_nodes
BEGIN SELECT RAISE(ABORT, 'immutable node'); END;
CREATE TRIGGER IF NOT EXISTS graph_nodes_no_delete BEFORE DELETE ON graph_nodes
BEGIN SELECT RAISE(ABORT, 'immutable node'); END;
CREATE TRIGGER IF NOT EXISTS graph_nodes_only_building BEFORE INSERT ON graph_nodes
WHEN (SELECT status FROM graph_snapshots WHERE id=NEW.snapshot_id) <> 'building'
BEGIN SELECT RAISE(ABORT, 'snapshot complete'); END;
CREATE TRIGGER IF NOT EXISTS graph_edges_no_update BEFORE UPDATE ON graph_edges
BEGIN SELECT RAISE(ABORT, 'immutable edge'); END;
CREATE TRIGGER IF NOT EXISTS graph_edges_no_delete BEFORE DELETE ON graph_edges
BEGIN SELECT RAISE(ABORT, 'immutable edge'); END;
CREATE TRIGGER IF NOT EXISTS graph_edges_only_building BEFORE INSERT ON graph_edges
WHEN (SELECT status FROM graph_snapshots WHERE id=NEW.snapshot_id) <> 'building'
BEGIN SELECT RAISE(ABORT, 'snapshot complete'); END;
CREATE TRIGGER IF NOT EXISTS graph_evidence_no_update BEFORE UPDATE ON graph_evidence
BEGIN SELECT RAISE(ABORT, 'immutable evidence'); END;
CREATE TRIGGER IF NOT EXISTS graph_evidence_no_delete BEFORE DELETE ON graph_evidence
BEGIN SELECT RAISE(ABORT, 'immutable evidence'); END;
CREATE TRIGGER IF NOT EXISTS graph_evidence_only_building BEFORE INSERT ON graph_evidence
WHEN (SELECT status FROM graph_snapshots WHERE id=NEW.snapshot_id) <> 'building'
BEGIN SELECT RAISE(ABORT, 'snapshot complete'); END;
CREATE TRIGGER IF NOT EXISTS graph_node_evidence_no_update BEFORE UPDATE ON graph_node_evidence
BEGIN SELECT RAISE(ABORT, 'immutable node evidence'); END;
CREATE TRIGGER IF NOT EXISTS graph_node_evidence_no_delete BEFORE DELETE ON graph_node_evidence
BEGIN SELECT RAISE(ABORT, 'immutable node evidence'); END;
CREATE TRIGGER IF NOT EXISTS graph_node_evidence_only_building BEFORE INSERT ON graph_node_evidence
WHEN (SELECT status FROM graph_snapshots WHERE id=NEW.snapshot_id) <> 'building'
BEGIN SELECT RAISE(ABORT, 'snapshot complete'); END;
CREATE TRIGGER IF NOT EXISTS graph_edge_evidence_no_update BEFORE UPDATE ON graph_edge_evidence
BEGIN SELECT RAISE(ABORT, 'immutable edge evidence'); END;
CREATE TRIGGER IF NOT EXISTS graph_edge_evidence_no_delete BEFORE DELETE ON graph_edge_evidence
BEGIN SELECT RAISE(ABORT, 'immutable edge evidence'); END;
CREATE TRIGGER IF NOT EXISTS graph_edge_evidence_only_building BEFORE INSERT ON graph_edge_evidence
WHEN (SELECT status FROM graph_snapshots WHERE id=NEW.snapshot_id) <> 'building'
BEGIN SELECT RAISE(ABORT, 'snapshot complete'); END;
CREATE TRIGGER IF NOT EXISTS graph_paths_no_update BEFORE UPDATE ON graph_paths
BEGIN SELECT RAISE(ABORT, 'immutable path'); END;
CREATE TRIGGER IF NOT EXISTS graph_paths_no_delete BEFORE DELETE ON graph_paths
BEGIN SELECT RAISE(ABORT, 'immutable path'); END;
CREATE TRIGGER IF NOT EXISTS graph_hypotheses_no_update BEFORE UPDATE ON graph_hypotheses
BEGIN SELECT RAISE(ABORT, 'immutable hypothesis'); END;
CREATE TRIGGER IF NOT EXISTS graph_hypotheses_no_delete BEFORE DELETE ON graph_hypotheses
BEGIN SELECT RAISE(ABORT, 'immutable hypothesis'); END;
CREATE TRIGGER IF NOT EXISTS graph_validations_no_update BEFORE UPDATE ON graph_validations
BEGIN SELECT RAISE(ABORT, 'immutable validation'); END;
CREATE TRIGGER IF NOT EXISTS graph_validations_no_delete BEFORE DELETE ON graph_validations
BEGIN SELECT RAISE(ABORT, 'immutable validation'); END;
CREATE TRIGGER IF NOT EXISTS graph_remediations_no_update BEFORE UPDATE ON graph_remediations
BEGIN SELECT RAISE(ABORT, 'immutable remediation'); END;
CREATE TRIGGER IF NOT EXISTS graph_remediations_no_delete BEFORE DELETE ON graph_remediations
BEGIN SELECT RAISE(ABORT, 'immutable remediation'); END;
PRAGMA user_version = 3;
