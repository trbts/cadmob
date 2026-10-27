/**
 * cadmob-worker  (v4 — banco de dados no Cloudflare D1)
 * ------------------------------------------------------------------
 */
const FORM_ROLES  = ['funcionario', 'admin', 'superadmin'];
const ADMIN_ROLES = ['admin', 'superadmin'];
const ROLES_VALIDAS = ['user', 'funcionario', 'admin', 'superadmin'];

const CAREEIRO_BOUNDS = { latMin: -5.00, latMax: -2.50, lngMin: -62.00, lngMax: -58.50 };
const PRECISAO_MAX_M = 50;

const LIMITES_POR_CAMPO = {
  base64: 300 * 1024,
  cnmRI: 32, cep: 16, niTitular: 32,
  idTransmitenteITBI: 32, idAdquirenteITBI: 32
};
const LIMITE_PADRAO = 5000;
const MAX_IMPORTACAO_POR_REQUISICAO = 25;
const MAX_FOTOS_EXTRAS = 2;

const SLOTS_IMAGEM = ['foto', 'anexo1', 'anexo2'];
const MAX_IMAGEM_BYTES = 300 * 1024;
const MIMES_IMAGEM = ['image/webp', 'image/jpeg', 'image/png'];
const DIAS_RETENCAO_PADRAO = 30;
const LOTE_MIGRACAO_LEGADO = 10;
const LOTE_MIGRACAO_BLOB = 20;
const LIMITE_LIMPEZA = 200;
const CAMINHO_COMP = '$.dados_imovel.DadosComplementares';

const TIPOS_SEGMENTO_LOTE = ['desmembrado', 'remembrado', 'fracao', 'outro'];
const REGEX_SEGMENTO = /^[A-Z0-9]{1,4}$/;

const CHAVES_TOPO_EDITAVEIS = [
  'bairro_imovel', 'quadra_imovel', 'lote_letra', 'unidade_imovel', 'status', 'responsavel',
  'segmento_lote', 'tipo_segmento_lote'
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

      const mAnexo = path.match(/^\/fichas\/([A-Za-z0-9_-]{1,64})\/anexos\/(foto|anexo1|anexo2)$/);
      if (mAnexo && method === 'GET') {
        await exigirRole(env, user, ADMIN_ROLES);
        return await rotaLerAnexo(env, mAnexo[1], mAnexo[2], origin);
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

      if (path === '/manutencao' && method === 'POST') {
        await exigirRole(env, user, ['superadmin']);
        return jsonResponse(await rotinaManutencao(env), 200, origin, env);
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
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      rotinaManutencao(env).catch((e) => console.error('manutencao_falhou', e))
    );
  }
};

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

async function rotaCriarFicha(request, env, user) {
  let payload;
  let imagens = [];

  const ct = (request.headers.get('Content-Type') || '').toLowerCase();
  if (ct.startsWith('multipart/form-data')) {
    let fd;
    try { fd = await request.formData(); }
    catch (e) { throw new HttpError(400, 'form_invalido', 'Corpo da requisição inválido.'); }

    const txt = fd.get('ficha');
    if (typeof txt !== 'string') throw new HttpError(400, 'json_invalido', 'Campo "ficha" ausente.');
    try { payload = JSON.parse(txt); }
    catch (e) { throw new HttpError(400, 'json_invalido', 'Campo "ficha" inválido.'); }

    for (const slot of SLOTS_IMAGEM) {
      const arq = fd.get(slot);
      if (!arq || typeof arq === 'string') continue;
      imagens.push(await lerArquivoImagem(arq, slot));
    }
  } else {
    try { payload = await request.json(); }
    catch (e) { throw new HttpError(400, 'json_invalido', 'Corpo da requisição inválido.'); }
    if (payload && payload.dados_imovel && typeof payload.dados_imovel === 'object') {
      imagens = extrairImagensBase64(payload.dados_imovel);
    }
  }

  const erro = validarFicha(payload);
  if (erro) throw new HttpError(400, 'validacao', erro);

  const complementar = payload.dados_imovel.DadosComplementares;
  const loc = complementar.localizacaoCadastral || {};

  const bairro   = String(loc.bairro || '').trim().toUpperCase();
  const quadra   = String(loc.quadra || '').trim().toUpperCase();
  const lote     = String(loc.lote   || '').trim().toUpperCase();
  const segmento = String(loc.segmento || '').trim().toUpperCase();
  const tipoSeg  = segmento ? String(loc.tipoSegmento || '').trim().toLowerCase() : '';
  const unidade  = String(payload.unidade_imovel || loc.unidade || '').trim();

  loc.segmento = segmento;
  loc.tipoSegmento = tipoSeg;
  complementar.localizacaoCadastral = loc;

  if (await existeDuplicada(env, bairro, quadra, lote, unidade, segmento)) {
    throw new HttpError(409, 'duplicado', 'Já existe cadastro para este lote/unidade.');
  }

  const fotoImg = imagens.find((i) => i.slot === 'foto') || null;
  const extras = imagens.filter((i) => i.slot !== 'foto')
    .sort((a, b) => a.slot.localeCompare(b.slot))
    .slice(0, MAX_FOTOS_EXTRAS);
  extras.forEach((img, i) => { img.slot = 'anexo' + (i + 1); });

  const fotoMeta = (complementar.foto && typeof complementar.foto === 'object') ? complementar.foto : null;
  if (fotoMeta && !fotoImg) {
    throw new HttpError(400, 'validacao', 'Arquivo da foto principal ausente.');
  }
  if (fotoImg) {
    const meta = fotoMeta || {};
    delete meta.base64;
    meta.tipo = fotoImg.mime;
    meta.tamanhoBytes = fotoImg.bytes.byteLength;
    meta.arquivo = true;
    complementar.foto = meta;
  } else {
    complementar.foto = null;
  }
  complementar.fotosAdicionais = extras.map((img) => ({
    tipo: img.mime, tamanhoBytes: img.bytes.byteLength, arquivo: true
  }));

  const agora = new Date().toISOString();
  const email = user.email || null;

  complementar.status           = 'pendente';
  complementar.origem           = complementar.origem || 'sinter';
  complementar.criado_em        = agora;
  complementar.criado_por_uid   = user.uid;
  complementar.criado_por_email = email;
  complementar.responsavel      = email;

  payload.bairro_imovel      = bairro;
  payload.quadra_imovel      = quadra;
  payload.lote_letra         = lote;
  payload.segmento_lote      = segmento;
  payload.tipo_segmento_lote = tipoSeg;
  payload.unidade_imovel     = unidade;
  payload.status             = 'pendente';
  payload.origem             = complementar.origem;
  payload.criado_em          = agora;
  payload.criado_por_uid     = user.uid;
  payload.criado_por_email   = email;
  payload.responsavel        = email;

  const id = crypto.randomUUID();
  const lista = [fotoImg, ...extras].filter(Boolean);

  await gravarMidia(env, id, lista);
  const stmts = [stmtInserirFicha(env, id, payload)];
  lista.forEach((img) => stmts.push(stmtInserirAnexo(env, id, img, agora)));
  stmts.push(stmtBumpVersao(env, agora));
  try {
    await env.DB.batch(stmts);
  } catch (e) {
    await apagarMidia(env, lista.map((i) => chaveMidia(id, i.slot))).catch(() => {});
    throw e;
  }

  return { ok: true, id };
}

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

  let totalBytes = 0;
  for (const k of chaves) {
    if (!caminhoPermitido(k)) {
      throw new HttpError(400, 'validacao', 'Campo não permitido: ' + k + '.');
    }
    const v = updates[k];
    // AGORA PERMITE OBJECT/ARRAY (para os Titulares e ITBI)
    if (v !== null && !['string', 'number', 'boolean', 'object'].includes(typeof v)) {
      throw new HttpError(400, 'validacao', 'Valor inválido para ' + k + '.');
    }
    
    if (typeof v === 'object' && v !== null) {
        totalBytes += JSON.stringify(v).length;
    } else if (typeof v === 'string') {
        totalBytes += v.length;
    }
  }
  
  if (totalBytes > 100 * 1024) {
    throw new HttpError(400, 'validacao', 'Payload de atualização muito grande.');
  }

  const vazioOuNull = (v) => v === null || v === undefined || String(v).trim() === '';
  for (const k of ['segmento_lote', LOC_PREFIXO + 'segmento']) {
    if (Object.prototype.hasOwnProperty.call(updates, k) && !vazioOuNull(updates[k]) &&
        !REGEX_SEGMENTO.test(String(updates[k]).trim().toUpperCase())) {
      throw new HttpError(400, 'validacao', 'Segmento do lote inválido (use até 4 letras/números).');
    }
  }
  for (const k of ['tipo_segmento_lote', LOC_PREFIXO + 'tipoSegmento']) {
    if (Object.prototype.hasOwnProperty.call(updates, k) && !vazioOuNull(updates[k]) &&
        !TIPOS_SEGMENTO_LOTE.includes(String(updates[k]).trim().toLowerCase())) {
      throw new HttpError(400, 'validacao', 'Classificação do segmento inválida.');
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

  [['bairro_imovel', 'bairro'], ['quadra_imovel', 'quadra'], ['lote_letra', 'lote']].forEach(([topo, lk]) => {
    if (has(topo)) doc[topo] = up(updates[topo]);
    else if (has(LOC_PREFIXO + lk)) doc[topo] = up(loc[lk]);
  });
  if (has('unidade_imovel')) doc.unidade_imovel = String(updates.unidade_imovel || '').trim();

  loc.segmento = String(
    has('segmento_lote') ? updates.segmento_lote
      : has(LOC_PREFIXO + 'segmento') ? updates[LOC_PREFIXO + 'segmento']
      : (loc.segmento != null ? loc.segmento : doc.segmento_lote)
  || '').trim().toUpperCase();
  loc.tipoSegmento = loc.segmento ? String(
    has('tipo_segmento_lote') ? updates.tipo_segmento_lote
      : has(LOC_PREFIXO + 'tipoSegmento') ? updates[LOC_PREFIXO + 'tipoSegmento']
      : (loc.tipoSegmento != null ? loc.tipoSegmento : doc.tipo_segmento_lote)
  || '').trim().toLowerCase() : '';
  comp.localizacaoCadastral = loc;
  doc.segmento_lote = loc.segmento;
  doc.tipo_segmento_lote = loc.tipoSegmento;

  if (has('status')) comp.status = doc.status;
  else if (has(STATUS_CAMINHO)) doc.status = comp.status;

  const agora = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE fichas SET
         bairro_imovel = ?1, quadra_imovel = ?2, lote_letra = ?3,
         unidade_imovel = ?4, unidade_norm = ?5,
         status = ?6, responsavel = ?7, atualizado_em = ?8, dados = ?9,
         segmento_lote = ?11
       WHERE id = ?10`
    ).bind(
      up(doc.bairro_imovel), up(doc.quadra_imovel), up(doc.lote_letra),
      String(doc.unidade_imovel || '').trim(), up(doc.unidade_imovel),
      String(doc.status || 'pendente'), doc.responsavel == null ? null : String(doc.responsavel),
      agora, JSON.stringify(doc), id, up(doc.segmento_lote)
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

async function rotaRemoverFicha(env, id) {
  const agora = new Date().toISOString();
  const { results: midias } = await env.DB.prepare(
    'SELECT slot, r2_chave FROM anexos WHERE ficha_id = ?1'
  ).bind(id).all();
  await apagarMidia(env, (midias || []).filter((m) => m.r2_chave).map((m) => m.r2_chave));
  const [res] = await env.DB.batch([
    env.DB.prepare('DELETE FROM fichas WHERE id = ?1').bind(id),
    env.DB.prepare('DELETE FROM anexos WHERE ficha_id = ?1').bind(id),
    stmtBumpVersao(env, agora)
  ]);
  if (!res.meta || res.meta.changes === 0) {
    throw new HttpError(404, 'nao_encontrada', 'Ficha não encontrada.');
  }
  return { ok: true };
}

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
  let ignoradas = 0, erros = 0, importadas = 0;
  const midiasImport = [];

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
    const segmentoBruto = String(loc.segmento || f.segmento_lote || '').trim().toUpperCase();
    const segmento = REGEX_SEGMENTO.test(segmentoBruto) ? segmentoBruto : '';
    const tipoBruto = String(loc.tipoSegmento || f.tipo_segmento_lote || '').trim().toLowerCase();
    const tipoSeg = segmento && TIPOS_SEGMENTO_LOTE.includes(tipoBruto) ? tipoBruto : '';
    loc.segmento = segmento; loc.tipoSegmento = tipoSeg;
    if (dc.localizacaoCadastral) dc.localizacaoCadastral = loc;

    if (bairro && quadra && lote) {
      const chave = [bairro, quadra, lote, segmento, unidade.toUpperCase()].join('|');
      if (vistos.has(chave) || await existeDuplicada(env, bairro, quadra, lote, unidade, segmento)) {
        ignoradas++; continue;
      }
      vistos.add(chave);
    }

    const criadoEm = dataIsoValida(dc.criado_em) || dataIsoValida(f.criado_em) || agora;
    const status = String(dc.status || f.status || 'pendente');

    const imagens = extrairImagensBase64(dadosImovel);

    const doc = {
      dados_imovel: dadosImovel,
      bairro_imovel: bairro, quadra_imovel: quadra, lote_letra: lote, unidade_imovel: unidade,
      segmento_lote: segmento, tipo_segmento_lote: tipoSeg,
      status,
      origem: 'import',
      criado_em: criadoEm,
      criado_por_uid: dc.criado_por_uid || null,
      criado_por_email: dc.criado_por_email || null,
      responsavel: dc.responsavel || null
    };
    const novoId = crypto.randomUUID();
    stmts.push(stmtInserirFicha(env, novoId, doc));
    imagens.forEach((img) => stmts.push(stmtInserirAnexo(env, novoId, img, agora)));
    midiasImport.push({ id: novoId, imgs: imagens });
    importadas++;
  }

  if (stmts.length) {
    const chavesGravadas = [];
    try {
      for (const m of midiasImport) {
        await gravarMidia(env, m.id, m.imgs);
        m.imgs.forEach((i) => chavesGravadas.push(chaveMidia(m.id, i.slot)));
      }
      stmts.push(stmtBumpVersao(env, agora));
      await env.DB.batch(stmts);
    } catch (e) {
      await apagarMidia(env, chavesGravadas).catch(() => {});
      throw e;
    }
  }

  return { ok: true, importadas, ignoradas, erros };
}

function dataIsoValida(v) {
  if (!v || typeof v !== 'string') return null;
  const t = new Date(v);
  return isNaN(t.getTime()) ? null : t.toISOString();
}

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

function normalizarUnidade(u) {
  return String(u || '').trim().toUpperCase();
}

async function existeDuplicada(env, bairro, quadra, lote, unidade, segmento) {
  const row = await env.DB.prepare(
    `SELECT 1 AS x FROM fichas
      WHERE bairro_imovel = ?1 AND quadra_imovel = ?2 AND lote_letra = ?3
        AND unidade_norm = ?4 AND segmento_lote = ?5
      LIMIT 1`
  ).bind(bairro, quadra, lote, normalizarUnidade(unidade), String(segmento || '').trim().toUpperCase()).first();
  return !!row;
}

function stmtInserirFicha(env, id, doc) {
  return env.DB.prepare(
    `INSERT INTO fichas
       (id, bairro_imovel, quadra_imovel, lote_letra, unidade_imovel, unidade_norm,
        status, origem, criado_em, atualizado_em,
        criado_por_uid, criado_por_email, responsavel, dados, segmento_lote)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)`
  ).bind(
    id,
    doc.bairro_imovel || '', doc.quadra_imovel || '', doc.lote_letra || '',
    doc.unidade_imovel || '', normalizarUnidade(doc.unidade_imovel),
    doc.status || 'pendente', doc.origem || 'sinter',
    doc.criado_em, doc.criado_em,
    doc.criado_por_uid || null, doc.criado_por_email || null, doc.responsavel || null,
    JSON.stringify(doc),
    String(doc.segmento_lote || '').trim().toUpperCase()
  );
}

function stmtInserirAnexo(env, fichaId, img, gravadoEm) {
  return env.DB.prepare(
    `INSERT OR REPLACE INTO anexos (ficha_id, slot, mime, tamanho, r2_chave, dados, gravado_em)
     VALUES (?1, ?2, ?3, ?4, ?5, x'', ?6)`
  ).bind(fichaId, img.slot, img.mime, img.bytes.byteLength, chaveMidia(fichaId, img.slot), gravadoEm);
}

function chaveMidia(fichaId, slot) { return 'fichas/' + fichaId + '/' + slot; }

function exigirR2(env) {
  if (!env.MIDIA) {
    throw new HttpError(500, 'midia_nao_configurada', 'Armazenamento de imagens (R2) não configurado no Worker.');
  }
}

async function gravarMidia(env, fichaId, imagens) {
  if (!imagens.length) return;
  exigirR2(env);
  const feitas = [];
  try {
    for (const img of imagens) {
      const chave = chaveMidia(fichaId