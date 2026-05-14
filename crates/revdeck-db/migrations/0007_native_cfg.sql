CREATE TABLE IF NOT EXISTS basic_blocks (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    function_key TEXT NOT NULL REFERENCES objects(object_key) ON DELETE CASCADE,
    start_address INTEGER NOT NULL,
    end_address INTEGER NOT NULL,
    size INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    terminator TEXT NOT NULL DEFAULT 'unknown',
    confidence REAL NOT NULL DEFAULT 0.5,
    source_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_basic_blocks_function
    ON basic_blocks(function_key, start_address);

CREATE TABLE IF NOT EXISTS instructions (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    function_key TEXT NOT NULL REFERENCES objects(object_key) ON DELETE CASCADE,
    block_key TEXT NOT NULL REFERENCES basic_blocks(object_key) ON DELETE CASCADE,
    address INTEGER NOT NULL,
    size INTEGER NOT NULL,
    bytes_hex TEXT NOT NULL,
    mnemonic TEXT NOT NULL,
    operands_text TEXT NOT NULL DEFAULT '',
    ordinal INTEGER NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    source_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_instructions_function
    ON instructions(function_key, address);

CREATE INDEX IF NOT EXISTS idx_instructions_block
    ON instructions(block_key, ordinal);

CREATE TABLE IF NOT EXISTS cfg_edges (
    edge_key TEXT PRIMARY KEY REFERENCES edges(edge_key) ON DELETE CASCADE,
    src_block_key TEXT NOT NULL REFERENCES basic_blocks(object_key) ON DELETE CASCADE,
    dst_block_key TEXT NOT NULL REFERENCES basic_blocks(object_key) ON DELETE CASCADE,
    edge_kind TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    source_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_cfg_edges_src
    ON cfg_edges(src_block_key, edge_kind);

CREATE INDEX IF NOT EXISTS idx_cfg_edges_dst
    ON cfg_edges(dst_block_key, edge_kind);
