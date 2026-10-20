/**
 * cadmob-worker  (v4 — banco de dados no Cloudflare D1)
 * ------------------------------------------------------------------
 * API única do sistema. A AUTENTICAÇÃO continua no Firebase Auth: todo
 * pedido traz um ID Token do Firebase, que o Worker valida (assinatura,
 * exp, aud, iss). Os DADOS (usuários/roles, fichas, listas) ficam no D1.
 *
 * Rotas
 *   GET    /health
 *   POST   /me                  cria o usuário (role 'user') se não existir e devolve {uid,email,nome,role}
 *   POST   /fichas              (funcionario|admin|superadmin) grava ficha nova
 *   GET    /fichas              (admin|superadmin)             lista todas as fichas
 *   GET    /fichas/versao       (admin|superadmin)             "carimbo" leve para o painel saber se mudou algo
 *   POST   /fichas/importar     (admin|superadmin)             importa um lote de fichas (backup JSON)
 *   PATCH  /fichas/:id          (admin|superadmin)             {updates:{ 'dados_imovel.a.b': valor, status: ... }}
 *   DELETE /fichas/:id          (superadmin)
 *   GET    /config/listas       (funcionario|admin|superadmin) {grupos:{bairros,ruas}}
 *   PUT    /config/listas       (superadmin)                   {grupos:{bairros,ruas}}
 *
 * Configuração no Cloudflare (Settings do Worker):
 *   Bindings   →  D1 database  →  variável  DB
 *   Variables  →  FIREBASE_PROJECT_ID  (texto)  ex.: cadmob
 *                 ALLOWED_ORIGINS       (texto)  ex.: https://trbts.github.io
 *   (FIREBASE_CLIENT_EMAIL e FIREBASE_PRIVATE_KEY NÃO são mais necessárias.)
 * ------------------------------------------------------------------
 */

const FORM_ROLES  = ['funcionario', 'admin', 'superadmin'];
const ADMIN_ROLES = ['admin', 'superadmin'];
const ROLES_VALIDAS = ['user', 'funcionario', 'admin', 'superadmin'];

// ---- Geolocalização (sanidade no servidor) ----
const CAREEIRO_BOUNDS = { latMin: -5.00, latMax: -2.50, lngMin: -62.00, lngMax: -58.50 };
const PRECISAO_MAX_M = 50;

// ---- Limites de tamanho por campo ----
const LIMITES_POR_CAMPO = {
  base64: 300 * 1024,
  cnmRI: 32, cep: 16, niTitular: 32,
  idTransmitenteITBI: 32, idAdquirenteITBI: 32
};
const LIMITE_PADRAO = 5000;
const MAX_IMPORTACAO_POR_REQUISICAO = 25;

// Chaves de topo que o painel pode editar via PATCH (além de 'dados_imovel.*')
const CHAVES_TOPO_EDITAVEIS = [
  'bairro_imovel', 'quadra_imovel', 'lote_letra', 'unidade_imovel', 'status', 'responsavel'
];
const CAMINHOS_PROIBIDOS = ['__proto__', 'constructor', 'prototype'];
const LOC_PREFIXO = 'dados_imovel.DadosComplementares.localizacaoCadastral.';
const STATUS_CAMINHO = 'dados_imovel.DadosComplementares.status';

class HttpError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

// ============================================================
// ENTRADA
// ============================================================
export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin, env) });
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = request.method;

    try {
      if (path === '/health') return jsonResponse({ ok: true }, 200, origin, env);

      if (!env.DB) throw new HttpError(500, 'sem_d1', 'Binding do D1 (DB) não configurado no Worker.');

      // Tudo abaixo exige usuário autenticado
      const user = await autenticar(request, env);

      if (path === '/me' && method === 'POST') {
        return jsonResponse(await rotaMe(request, env, user), 200, origin, env);
      }

      if (path === '/fichas' && method === 'POST') {
        await exigirRole(env, user, FORM_ROLES, 'Sua conta ainda não foi aprovada para enviar fichas.');
        return jsonResponse(await rotaCriarFicha(request, env, user), 200, origin, env);
      }
      if (path === '/fichas' && method === 'GET') {
        await exigirRole(env, user, ADMIN_ROLES);
        return jsonResponse(await rotaListarFichas(env), 200, origin, env);
      }
      if (path === '/fichas/versao' && method === 'GET') {
        await exigirRole(env, user, ADMIN_ROLES);
        return jsonResponse(await rotaVersao(env), 200, origin, env);
      }
      if (path === '/fichas/importar' && method === 'POST') {
        await exigirRole(env, user, ADMIN_ROLES);
        return jsonResponse(await rotaImportar(request, env), 200, origin, env);
      }

      const mFicha = path.match(/^\/fichas\/([A-Za-z0-9_-]{1,64})$/);
      if (mFicha && method === 'PATCH') {
        await exigirRole(env, user, ADMIN_ROLES);
        return jsonResponse(await rotaAtualizarFicha(request, env, mFicha[1]), 200, origin, env);
      }
      if (mFicha && method === 'DELETE') {
        await exigirRole(env, user, ['superadmin'], 'Apenas o Super Admin pode remover fichas.');
        return jsonResponse(await rotaRemoverFicha(env, mFicha[1]), 200, origin, env);
      }

      if (path === '/config/listas' && method === 'GET') {
        await exigirRole(env, user, FORM_ROLES);
        return jsonResponse(await rotaLerListas(env), 200, origin, env);
      }
      if (path === '/config/listas' && method === 'PUT') {
        await exigirRole(env, user, ['superadmin']);
        return jsonResponse(await rotaSalvarListas(request, env), 200, origin, env);
      }

      throw new HttpError(404, 'rota_nao_encontrada', 'Rota não encontrada.');
    } catch (err) {
      if (err instanceof HttpError) {
        return jsonResponse({ error: err.code, message: err.message }, err.status, origin, env);
      }
      console.error('erro_nao_tratado', err);
      return jsonResponse(
        { error: 'erro_interno', message: 'Erro interno no servidor.' },
        500, origin, env
      );
    }
  }
};

// ============================================================
// AUTENTICAÇÃO / AUTORIZAÇÃO
// ============================================================
async function autenticar(request, env) {
  const m = (request.headers.get('Authorization') || '').match(/^Bearer (.+)$/);
  if (!m) throw new HttpError(401, 'sem_token', 'Token de autenticação ausente.');
  try {
    return await verifyFirebaseIdToken(m[1], env.FIREBASE_PROJECT_ID);
  } catch (err) {
    throw new HttpError(401, 'token_invalido', 'Sessão inválida ou expirada. Faça login novamente.');
  }
}

async function getRole(env, uid) {
  const row = await env.DB.prepare('SELECT role FROM usuarios WHERE uid = ?1').bind(uid).first();
  const role = row ? String(row.role || 'user').toLowerCase() : 'user';
  return ROLES_VALIDAS.includes(role) ? role : 'user';
}

async function exigirRole(env, user, permitidas, mensagem) {
  const role = await getRole(env, user.uid);
  if (!permitidas.includes(role)) {
    throw new HttpError(403, 'sem_permissao', mensagem || 'Você não tem permissão para esta ação.');
  }
  return role;
}

// ============================================================
// ROTA: POST /me
// ============================================================
async function rotaMe(request, env, user) {
  let body = {};
  try { body = await request.json(); } catch (e) { /* corpo opcional */ }

  const email = String(user.email || '');
  const nome = String(
    (body && body.nome) || user.nome || email.split('@')[0] || 'Usuário'
  ).trim().slice(0, 120) || 'Usuário';

  await env.DB.prepare(
    `INSERT INTO usuarios (uid, email, nome, role, criado_em)
     VALUES (?1, ?2, ?3, 'user', ?4)
     ON CONFLICT(uid) DO UPDATE SET
       email = CASE WHEN excluded.email <> '' THEN excluded.email ELSE usuarios.email END`
  ).bind(user.uid, email, nome, new Date().toISOString()).run();

  const row = await env.DB.prepare(
    'SELECT uid, email, nome, role FROM usuarios WHERE uid = ?1'
  ).bind(user.uid).first();

  const role = String(row.role || 'user').toLowerCase();
  return {
    uid: row.uid, email: row.email, nome: row.nome,
    role: ROLES_VALIDAS.includes(role) ? role : 'user'
  };
}

// ============================================================
// ROTA: POST /fichas
// ============================================================
async function rotaCriarFicha(request, env, user) {
  let payload;
  try { payload = await request.json(); }
  catch (e) { throw new HttpError(400, 'json_invalido', 'Corpo da requisição inválido.'); }

  const erro = validarFicha(payload);
  if (erro) throw new HttpError(400, 'validacao', erro);

  const complementar = payload.dados_imovel.DadosComplementares;
  const loc = complementar.localizacaoCadastral || {};

  const bairro  = String(loc.bairro || '').trim().toUpperCase();
  const quadra  = String(loc.quadra || '').trim().toUpperCase();
  const lote    = String(loc.lote   || '').trim().toUpperCase();
  const unidade = String(payload.unidade_imovel || loc.unidade || '').trim();

  if (await existeDuplicada(env, bairro, quadra, lote, unidade)) {
    throw new HttpError(409, 'duplicado', 'Já existe cadastro para este lote/unidade.');
  }

  const agora = new Date().toISOString();
  const email = user.email || null;

  // Campos controlados pelo servidor — dentro de DadosComplementares
  complementar.status           = 'pendente';
  complementar.origem           = complementar.origem || 'sinter';
  complementar.criado_em        = agora;
  complementar.criado_por_uid   = user.uid;
  complementar.criado_por_email = email;
  complementar.responsavel      = email;

  // Espelhamento no topo
  payload.bairro_imovel    = bairro;
  payload.quadra_imovel    = quadra;
  payload.lote_letra       = lote;
  payload.unidade_imovel   = unidade;
  payload.status           = 'pendente';
  payload.origem           = complementar.origem;
  payload.criado_em        = agora;
  payload.criado_por_uid   = user.uid;
  payload.criado_por_email = email;
  payload.responsavel      = email;

  const id = crypto.randomUUID();
  await env.DB.batch([
    stmtInserirFicha(env, id, payload),
    stmtBumpVersao(env, agora)
  ]);

  return { ok: true, id };
}

// ============================================================
// ROTA: GET /fichas  e  GET /fichas/versao
// ============================================================
async function rotaListarFichas(env) {
  const { results } = await env.DB.prepare(
    'SELECT * FROM fichas ORDER BY criado_em DESC'
  ).all();
  return { fichas: (results || []).map(linhaParaDoc) };
}

async function rotaVersao(env) {
  const row = await env.DB.prepare(
    "SELECT valor FROM config WHERE chave = 'fichas_versao'"
  ).first();
  return { versao: row ? row.valor : '0' };
}

// ============================================================
// ROTA: PATCH /fichas/:id
// ============================================================
async function rotaAtualizarFicha(request, env, id) {
  let body;
  try { body = await request.json(); }
  catch (e) { throw new HttpError(400, 'json_invalido', 'Corpo da requisição inválido.'); }

  const updates = body && body.updates;
  if (!updates || typeof updates !== 'object' || Array.isArray(updates)) {
    throw new HttpError(400, 'validacao', 'Campo "updates" ausente ou inválido.');
  }
  const chaves = Object.keys(updates);
  if (!chaves.length || chaves.length > 200) {
    throw new HttpError(400, 'validacao', 'Quantidade de campos inválida.');
  }

  for (const k of chaves) {
    if (!caminhoPermitido(k)) {
      throw new HttpError(400, 'validacao', 'Campo não permitido: ' + k + '.');
    }
    const v = updates[k];
    if (v !== null && !['string', 'number', 'boolean'].includes(typeof v)) {
      throw new HttpError(400, 'validacao', 'Valor inválido para ' + k + '.');
    }
    if (typeof v === 'string' && v.length > LIMITE_PADRAO) {
      throw new HttpError(400, 'validacao', 'Campo "' + k + '" excede o tamanho máximo permitido.');
    }
  }

  const row = await env.DB.prepare('SELECT dados FROM fichas WHERE id = ?1').bind(id).first();
  if (!row) throw new HttpError(404, 'nao_encontrada', 'Ficha não encontrada.');

  const doc = JSON.parse(row.dados);
  doc.dados_imovel = doc.dados_imovel || {};
  doc.dados_imovel.DadosComplementares = doc.dados_imovel.DadosComplementares || {};

  for (const k of chaves) definirPorCaminho(doc, k, updates[k]);

  const has = (k) => Object.prototype.hasOwnProperty.call(updates, k);
  const comp = doc.dados_imovel.DadosComplementares;
  const loc  = comp.localizacaoCadastral || {};
  const up   = (s) => String(s == null ? '' : s).trim().toUpperCase();

  // Mantém topo e bloco aninhado coerentes
  [['bairro_imovel', 'bairro'], ['quadra_imovel', 'quadra'], ['lote_letra', 'lote']].forEach(([topo, lk]) => {
    if (has(topo)) doc[topo] = up(updates[topo]);
    else if (has(LOC_PREFIXO + lk)) doc[topo] = up(loc[lk]);
  });
  if (has('unidade_imovel')) doc.unidade_imovel = String(updates.unidade_imovel || '').trim();

  if (has('status')) comp.status = doc.status;
  else if (has(STATUS_CAMINHO)) doc.status = comp.status;

  const agora = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE fichas SET
         bairro_imovel = ?1, quadra_imovel = ?2, lote_letra = ?3,
         unidade_imovel = ?4, unidade_norm = ?5,
         status = ?6, responsavel = ?7, atualizado_em = ?8, dados = ?9
       WHERE id = ?10`
    ).bind(
      up(doc.bairro_imovel), up(doc.quadra_imovel), up(doc.lote_letra),
      String(doc.unidade_imovel || '').trim(), up(doc.unidade_imovel),
      String(doc.status || 'pendente'), doc.responsavel == null ? null : String(doc.responsavel),
      agora, JSON.stringify(doc), id
    ),
    stmtBumpVersao(env, agora)
  ]);

  return { ok: true };
}

function caminhoPermitido(k) {
  if (CHAVES_TOPO_EDITAVEIS.includes(k)) return true;
  if (!k.startsWith('dados_imovel.')) return false;
  return k.split('.').every(
    (seg) => /^[A-Za-z0-9_]{1,60}$/.test(seg) && !CAMINHOS_PROIBIDOS.includes(seg)
  );
}

function definirPorCaminho(obj, caminho, valor) {
  const partes = caminho.split('.');
  let cur = obj;
  for (let i = 0; i < partes.length - 1; i++) {
    const p = partes[i];
    if (!cur[p] || typeof cur[p] !== 'object' || Array.isArray(cur[p])) cur[p] = {};
    cur = cur[p];
  }
  cur[partes[partes.length - 1]] = valor;
}

// ============================================================
// ROTA: DELETE /fichas/:id
// ============================================================
async function rotaRemoverFicha(env, id) {
  const agora = new Date().toISOString();
  const [res] = await env.DB.batch([
    env.DB.prepare('DELETE FROM fichas WHERE id = ?1').bind(id),
    stmtBumpVersao(env, agora)
  ]);
  if (!res.meta || res.meta.changes === 0) {
    throw new HttpError(404, 'nao_encontrada', 'Ficha não encontrada.');
  }
  return { ok: true };
}

// ============================================================
// ROTA: POST /fichas/importar
// ============================================================
async function rotaImportar(request, env) {
  let body;
  try { body = await request.json(); }
  catch (e) { throw new HttpError(400, 'json_invalido', 'Corpo da requisição inválido.'); }

  const lista = body && Array.isArray(body.fichas) ? body.fichas : null;
  if (!lista || !lista.length) throw new HttpError(400, 'validacao', 'Nenhuma ficha enviada.');
  if (lista.length > MAX_IMPORTACAO_POR_REQUISICAO) {
    throw new HttpError(400, 'validacao',
      'Envie no máximo ' + MAX_IMPORTACAO_POR_REQUISICAO + ' fichas por requisição.');
  }

  const agora = new Date().toISOString();
  const stmts = [];
  const vistos = new Set();
  let ignoradas = 0, erros = 0;

  for (const f of lista) {
    if (!f || typeof f !== 'object' || Array.isArray(f)) { erros++; continue; }

    const dadosImovel = (f.dados_imovel && typeof f.dados_imovel === 'object') ? f.dados_imovel : f;
    if (Array.isArray(dadosImovel) || verificarTamanhos(dadosImovel, 0)) { erros++; continue; }

    const dc  = (dadosImovel.DadosComplementares && typeof dadosImovel.DadosComplementares === 'object')
      ? dadosImovel.DadosComplementares : (dadosImovel.DadosComplementares = {});
    const loc = dc.localizacaoCadastral || {};

    const bairro  = String(loc.bairro || '').trim().toUpperCase();
    const quadra  = String(loc.quadra || '').trim().toUpperCase();
    const lote    = String(loc.lote   || '').trim().toUpperCase();
    const unidade = String(loc.unidade || f.unidade_imovel || '').trim();

    // Evita duplicar o que já existe (só quando há localização preenchida)
    if (bairro && quadra && lote) {
      const chave = [bairro, quadra, lote, unidade.toUpperCase()].join('|');
      if (vistos.has(chave) || await existeDuplicada(env, bairro, quadra, lote, unidade)) {
        ignoradas++; continue;
      }
      vistos.add(chave);
    }

    const criadoEm = dataIsoValida(dc.criado_em) || dataIsoValida(f.criado_em) || agora;
    const status = String(dc.status || f.status || 'pendente');

    const doc = {
      dados_imovel: dadosImovel,
      bairro_imovel: bairro, quadra_imovel: quadra, lote_letra: lote, unidade_imovel: unidade,
      status,
      origem: 'import',
      criado_em: criadoEm,
      criado_por_uid: dc.criado_por_uid || null,
      criado_por_email: dc.criado_por_email || null,
      responsavel: dc.responsavel || null
    };
    stmts.push(stmtInserirFicha(env, crypto.randomUUID(), doc));
  }

  if (stmts.length) {
    stmts.push(stmtBumpVersao(env, agora));
    await env.DB.batch(stmts);
  }

  return { ok: true, importadas: stmts.length ? stmts.length - 1 : 0, ignoradas, erros };
}

function dataIsoValida(v) {
  if (!v || typeof v !== 'string') return null;
  const t = new Date(v);
  return isNaN(t.getTime()) ? null : t.toISOString();
}

// ============================================================
// ROTAS: /config/listas
// ============================================================
async function rotaLerListas(env) {
  const row = await env.DB.prepare("SELECT valor FROM config WHERE chave = 'listas'").first();
  let grupos = {};
  if (row) {
    try { grupos = (JSON.parse(row.valor) || {}).grupos || {}; } catch (e) { grupos = {}; }
  }
  return { grupos };
}

async function rotaSalvarListas(request, env) {
  let body;
  try { body = await request.json(); }
  catch (e) { throw new HttpError(400, 'json_invalido', 'Corpo da requisição inválido.'); }

  const grupos = body && body.grupos;
  if (!grupos || typeof grupos !== 'object' || Array.isArray(grupos)) {
    throw new HttpError(400, 'validacao', 'Campo "grupos" ausente ou inválido.');
  }
  const texto = JSON.stringify({ grupos });
  if (texto.length > 200 * 1024) throw new HttpError(400, 'validacao', 'Listas grandes demais.');

  await env.DB.prepare(
    `INSERT INTO config (chave, valor, atualizado_em) VALUES ('listas', ?1, ?2)
     ON CONFLICT(chave) DO UPDATE SET valor = excluded.valor, atualizado_em = excluded.atualizado_em`
  ).bind(texto, new Date().toISOString()).run();

  return { ok: true };
}

// ============================================================
// D1 — helpers
// ============================================================
function normalizarUnidade(u) {
  return String(u || '').trim().toUpperCase();
}

async function existeDuplicada(env, bairro, quadra, lote, unidade) {
  const row = await env.DB.prepare(
    `SELECT 1 AS x FROM fichas
      WHERE bairro_imovel = ?1 AND quadra_imovel = ?2 AND lote_letra = ?3 AND unidade_norm = ?4
      LIMIT 1`
  ).bind(bairro, quadra, lote, normalizarUnidade(unidade)).first();
  return !!row;
}

function stmtInserirFicha(env, id, doc) {
  return env.DB.prepare(
    `INSERT INTO fichas
       (id, bairro_imovel, quadra_imovel, lote_letra, unidade_imovel, unidade_norm,
        status, origem, criado_em, atualizado_em,
        criado_por_uid, criado_por_email, responsavel, dados)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)`
  ).bind(
    id,
    doc.bairro_imovel || '', doc.quadra_imovel || '', doc.lote_letra || '',
    doc.unidade_imovel || '', normalizarUnidade(doc.unidade_imovel),
    doc.status || 'pendente', doc.origem || 'sinter',
    doc.criado_em, doc.criado_em,
    doc.criado_por_uid || null, doc.criado_por_email || null, doc.responsavel || null,
    JSON.stringify(doc)
  );
}

function stmtBumpVersao(env, agora) {
  return env.DB.prepare(
    `INSERT INTO config (chave, valor, atualizado_em) VALUES ('fichas_versao', ?1, ?2)
     ON CONFLICT(chave) DO UPDATE SET valor = excluded.valor, atualizado_em = excluded.atualizado_em`
  ).bind(crypto.randomUUID(), agora);
}

// Monta o documento no mesmo formato que o painel já consumia do Firestore
function linhaParaDoc(row) {
  let doc = {};
  try { doc = JSON.parse(row.dados) || {}; } catch (e) { doc = {}; }
  return Object.assign(doc, {
    id: row.id,
    bairro_imovel: row.bairro_imovel,
    quadra_imovel: row.quadra_imovel,
    lote_letra: row.lote_letra,
    unidade_imovel: row.unidade_imovel,
    status: row.status,
    origem: row.origem,
    criado_em: row.criado_em,
    atualizado_em: row.atualizado_em,
    criado_por_uid: row.criado_por_uid,
    criado_por_email: row.criado_por_email,
    responsavel: row.responsavel
  });
}

// ============================================================
// VALIDAÇÃO DE NEGÓCIO
// ============================================================
function validarFicha(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return 'Payload ausente ou inválido.';
  }
  const dadosImovel = payload.dados_imovel;
  if (!dadosImovel || typeof dadosImovel !== 'object' || Array.isArray(dadosImovel)) {
    return 'Bloco "dados_imovel" ausente ou inválido.';
  }
  const complementar = dadosImovel.DadosComplementares;
  if (!complementar || typeof complementar !== 'object' || Array.isArray(complementar)) {
    return 'Bloco "dados_imovel.DadosComplementares" ausente ou inválido.';
  }
  const loc = complementar.localizacaoCadastral;
  if (!loc || typeof loc !== 'object') {
    return 'Localização cadastral ausente (bairro/quadra/lote).';
  }
  for (const campo of ['bairro', 'quadra', 'lote']) {
    if (!loc[campo] || !String(loc[campo]).trim()) {
      return 'Campo obrigatório ausente: ' + campo + '.';
    }
  }
  const erroGeo = validarGeolocalizacao(complementar.foto);
  if (erroGeo) return erroGeo;

  return verificarTamanhos(payload, 0);
}

function verificarTamanhos(obj, profundidade) {
  if (profundidade > 8) return 'Estrutura do payload excede a profundidade esperada.';
  if (obj == null || typeof obj === 'string') return null;

  if (Array.isArray(obj)) {
    for (const item of obj) {
      const r = verificarTamanhos(item, profundidade + 1);
      if (r) return r;
    }
    return null;
  }

  if (typeof obj === 'object') {
    const chaves = Object.keys(obj);
    if (chaves.length > 150 && profundidade === 0) return 'Payload com número de campos inesperado.';
    for (const chave of chaves) {
      const valor = obj[chave];
      if (typeof valor === 'string') {
        const limite = LIMITES_POR_CAMPO[chave] || LIMITE_PADRAO;
        if (valor.length > limite) return 'Campo "' + chave + '" excede o tamanho máximo permitido.';
      } else if (valor && typeof valor === 'object') {
        const r = verificarTamanhos(valor, profundidade + 1);
        if (r) return r;
      }
    }
  }
  return null;
}

function validarGeolocalizacao(foto) {
  if (!foto || typeof foto !== 'object') return null;

  const tem = (v) => v !== undefined && v !== null && v !== '';
  const temLat = tem(foto.latitude), temLng = tem(foto.longitude), temAcc = tem(foto.precisaoM);
  if (!temLat && !temLng && !temAcc) return null;

  if (!temLat || !temLng) return 'Geolocalização inconsistente: latitude/longitude incompletas.';

  const lat = Number(foto.latitude), lng = Number(foto.longitude);
  if (!Number.isFinite(lat) || lat < -90 || lat > 90) return 'Latitude inválida.';
  if (!Number.isFinite(lng) || lng < -180 || lng > 180) return 'Longitude inválida.';

  if (lat < CAREEIRO_BOUNDS.latMin || lat > CAREEIRO_BOUNDS.latMax ||
      lng < CAREEIRO_BOUNDS.lngMin || lng > CAREEIRO_BOUNDS.lngMax) {
    return 'Coordenadas fora dos limites do município do Careiro.';
  }

  if (temAcc) {
    const acc = Number(foto.precisaoM);
    if (!Number.isFinite(acc) || acc <= 0) return 'Precisão de geolocalização inválida.';
    if (acc > PRECISAO_MAX_M) {
      return 'Precisão de geolocalização acima do aceitável (' + Math.round(acc) + ' m > ' +
        PRECISAO_MAX_M + ' m). Refaça a foto em uma área mais aberta.';
    }
  }
  return null;
}

// ============================================================
// FIREBASE AUTH — verificação do ID Token (sem Admin SDK)
// ============================================================
let jwksCache = null;
let jwksCacheExp = 0;

async function getFirebasePublicJWKS() {
  const agora = Date.now();
  if (jwksCache && agora < jwksCacheExp) return jwksCache;

  const resp = await fetch(
    'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'
  );
  if (!resp.ok) throw new Error('falha_ao_buscar_jwks');
  const dados = await resp.json();

  const m = (resp.headers.get('cache-control') || '').match(/max-age=(\d+)/);
  const maxAgeMs = m ? parseInt(m[1], 10) * 1000 : 3600000;

  jwksCache = dados.keys;
  jwksCacheExp = agora + maxAgeMs;
  return jwksCache;
}

async function verifyFirebaseIdToken(idToken, projectId) {
  const partes = idToken.split('.');
  if (partes.length !== 3) throw new Error('token_malformado');
  const [headerB64, payloadB64, sigB64] = partes;

  const header = JSON.parse(b64urlDecodeToString(headerB64));
  const payload = JSON.parse(b64urlDecodeToString(payloadB64));

  if (header.alg !== 'RS256') throw new Error('algoritmo_invalido');

  const keys = await getFirebasePublicJWKS();
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error('chave_publica_nao_encontrada');

  const cryptoKey = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
  );
  const valido = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5', cryptoKey,
    b64urlDecodeToBytes(sigB64),
    new TextEncoder().encode(headerB64 + '.' + payloadB64)
  );
  if (!valido) throw new Error('assinatura_invalida');

  const agora = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < agora) throw new Error('token_expirado');
  if (typeof payload.iat !== 'number' || payload.iat > agora + 60) throw new Error('token_futuro');
  if (payload.aud !== projectId) throw new Error('aud_invalido');
  if (payload.iss !== 'https://securetoken.google.com/' + projectId) throw new Error('iss_invalido');
  if (!payload.sub) throw new Error('sub_ausente');

  return { uid: payload.sub, email: payload.email || null, nome: payload.name || null };
}

// ============================================================
// UTIL — base64url
// ============================================================
function b64urlDecodeToBytes(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function b64urlDecodeToString(str) {
  return new TextDecoder().decode(b64urlDecodeToBytes(str));
}

// ============================================================
// CORS / RESPOSTAS
// ============================================================
function corsHeaders(origin, env) {
  const permitidas = (env.ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  const allowOrigin = permitidas.includes(origin) ? origin : (permitidas[0] || 'null');
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}
function jsonResponse(data, status, origin, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders(origin, env) }
  });
}
