-- ============================================================
-- Cadastro Imobiliário · Careiro — schema do Cloudflare D1
-- Execute no console do D1 (Storage & databases → D1 → seu banco → Console)
-- ============================================================

-- Usuários (a autenticação continua no Firebase Auth; aqui fica só a role)
CREATE TABLE IF NOT EXISTS usuarios (
  uid        TEXT PRIMARY KEY,               -- UID do Firebase Auth
  email      TEXT NOT NULL DEFAULT '',
  nome       TEXT NOT NULL DEFAULT '',
  role       TEXT NOT NULL DEFAULT 'user',   -- user | funcionario | admin | superadmin
  criado_em  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email);

-- Fichas: colunas para consulta + documento completo em JSON (coluna "dados")
CREATE TABLE IF NOT EXISTS fichas (
  id               TEXT PRIMARY KEY,
  bairro_imovel    TEXT NOT NULL DEFAULT '',
  quadra_imovel    TEXT NOT NULL DEFAULT '',
  lote_letra       TEXT NOT NULL DEFAULT '',
  unidade_imovel   TEXT NOT NULL DEFAULT '',
  unidade_norm     TEXT NOT NULL DEFAULT '',   -- unidade em MAIÚSCULAS, para checar duplicidade
  status           TEXT NOT NULL DEFAULT 'pendente',
  origem           TEXT NOT NULL DEFAULT 'sinter',
  criado_em        TEXT NOT NULL,
  atualizado_em    TEXT NOT NULL,
  criado_por_uid   TEXT,
  criado_por_email TEXT,
  responsavel      TEXT,
  dados            TEXT NOT NULL               -- documento completo (JSON)
);
CREATE INDEX IF NOT EXISTS idx_fichas_lote   ON fichas(bairro_imovel, quadra_imovel, lote_letra, unidade_norm);
CREATE INDEX IF NOT EXISTS idx_fichas_criado ON fichas(criado_em DESC);

-- Configurações (listas de bairros/ruas e versão das fichas para o painel)
CREATE TABLE IF NOT EXISTS config (
  chave          TEXT PRIMARY KEY,
  valor          TEXT NOT NULL,
  atualizado_em  TEXT
);
