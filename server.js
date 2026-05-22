require('dotenv').config()
const express = require('express')
const { createClient } = require('@supabase/supabase-js')
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
app.use(cors())
app.use(express.json())

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY,
)

// CHAVE MESTRA: Mantenha esta chave segura!
const SECRET_KEY = 'sua_chave_secreta_aqui'

// -----------------------------------------------------------
// MIDDLEWARE: A BARREIRA DE SEGURANÇA
// -----------------------------------------------------------
function verificarToken(req, res, next) {
  const token = req.headers['authorization']

  if (!token) {
    return res
      .status(403)
      .json({ erro: 'Acesso negado. Faça login para continuar.' })
  }

  try {
    // Remove a palavra "Bearer " caso o app a envie
    const tokenLimpo = token.startsWith('Bearer ') ? token.split(' ')[1] : token
    const verificado = jwt.verify(tokenLimpo, SECRET_KEY)

    req.usuarioLogado = verificado // Dados do token (id, email) ficam disponíveis aqui
    next()
  } catch (err) {
    res
      .status(401)
      .json({
        erro: 'Sessão expirada ou token inválido. Faça login novamente.',
      })
  }
}

// -----------------------------------------------------------
// ROTAS PÚBLICAS (Qualquer um pode ver para escolher o serviço)
// -----------------------------------------------------------

app.get('/categorias', async (req, res) => {
  const { data, error } = await supabase.from('categorias').select('*')
  if (error) return res.status(400).json(error)
  res.json(data)
})

app.get('/servicos/:id', async (req, res) => {
  const { id } = req.params
  const { data, error } = await supabase
    .from('servicos')
    .select('*')
    .eq('id_categoria', id)
  if (error) return res.status(400).json(error)
  res.json(data)
})

app.get('/perfil-profissional/:id', async (req, res) => {
  const { id } = req.params
  const { data, error } = await supabase
    .from('usuarios')
    .select(
      `id_usuario, nome, tipo_perfil, profissionais_detalhes ( bio, raio_atendimento_km )`,
    )
    .eq('id_usuario', id)

  if (data && data.length === 0)
    return res.status(404).json({ mensagem: 'Profissional não encontrado!' })
  if (error) return res.status(400).json(error)
  res.json(data[0])
})

app.get('/horarios/:id', async (req, res) => {
  const { id } = req.params
  const { data, error } = await supabase
    .from('horarios_trabalho')
    .select('*')
    .eq('id_profissional', id)
    .eq('esta_ativo', true)
    .order('dia_semana', { ascending: true })

  if (error) return res.status(400).json(error)
  res.json(data)
})

// -----------------------------------------------------------
// ROTAS DE AUTENTICAÇÃO (Cadastro e Login)
// -----------------------------------------------------------

app.post('/auth/cadastro', async (req, res) => {
  try {
    const { nome, email, senha, telefone, tipo_perfil, cpf } = req.body
    const senhaCripto = await bcrypt.hash(senha, 10)

    const { data, error } = await supabase
      .from('usuarios')
      .insert([
        {
          nome,
          email,
          senha: senhaCripto,
          telefone,
          cpf,
          tipo_perfil: tipo_perfil ? tipo_perfil.toUpperCase() : 'CLIENTE',
        },
      ])
      .select()

    if (error)
      return res
        .status(400)
        .json({ erro: 'Erro no banco', detalhes: error.message })
    res.status(201).json(data[0])
  } catch (error) {
    res.status(500).json({ erro: 'Falha interna', detalhes: error.message })
  }
})

app.post('/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body
    const { data: usuario, error } = await supabase
      .from('usuarios')
      .select('*')
      .eq('email', email)
      .single()

    if (!usuario || error)
      return res.status(401).json({ erro: 'E-mail ou senha incorretos.' })

    const senhaValida = await bcrypt.compare(senha, usuario.senha)
    if (!senhaValida)
      return res.status(401).json({ erro: 'E-mail ou senha incorretos.' })

    const token = jwt.sign(
      { id: usuario.id_usuario, email: usuario.email },
      SECRET_KEY,
      { expiresIn: '7d' },
    )

    res.json({
      token,
      usuario: {
        id: usuario.id_usuario,
        nome: usuario.nome,
        tipo: usuario.tipo_perfil,
      },
    })
  } catch (error) {
    res.status(500).json({ erro: error.message })
  }
})

// -----------------------------------------------------------
// ROTAS PROTEGIDAS (Só quem tem o TOKEN pode acessar)
// -----------------------------------------------------------

// Listar agendamentos do cliente (PROTEGIDA)
app.get('/meus-agendamentos/:id_cliente', verificarToken, async (req, res) => {
  const { id_cliente } = req.params
  try {
    const { data, error } = await supabase
      .from('agendamentos')
      .select(
        `
                id_combina, data_hora_inicio, valor_total, status_agendamento,
                servicos ( nome_servico ),
                profissionais_detalhes!id_profissional ( usuarios ( nome ) )
            `,
      )
      .eq('id_cliente', id_cliente)
      .order('data_hora_inicio', { ascending: true })

    if (error) throw error
    res.json(data)
  } catch (error) {
    res
      .status(500)
      .json({ erro: 'Erro ao buscar agendamentos', detalhes: error.message })
  }
})

// Confirmar novo agendamento com validação (PROTEGIDA)
app.post('/confirmar-agendamento', verificarToken, async (req, res) => {
  const { id_cliente, id_profissional, id_servico, data_hora_inicio } = req.body
  try {
    const { data: servico } = await supabase
      .from('servicos')
      .select('*')
      .eq('id_servico', id_servico)
      .single()
    if (!servico)
      return res.status(404).json({ error: 'Serviço não encontrado' })

    const inicio = new Date(data_hora_inicio)
    const fim = new Date(
      inicio.getTime() + servico.duracao_estimada_minutos * 60000,
    )

    const { data: conflitos } = await supabase
      .from('agendamentos')
      .select('*')
      .eq('id_profissional', id_profissional)
      .neq('status_agendamento', 'CANCELADO')
      .lt('data_hora_inicio', fim.toISOString())
      .gt('data_hora_fim', inicio.toISOString())

    if (conflitos && conflitos.length > 0)
      return res.status(400).json({ error: 'Horário já ocupado.' })

    const { data: novo, error: err } = await supabase
      .from('agendamentos')
      .insert([
        {
          id_cliente,
          id_profissional,
          id_servico,
          data_hora_inicio: inicio.toISOString(),
          data_hora_fim: fim.toISOString(),
          valor_total: servico.preco,
          status_agendamento: 'CONFIRMADO',
        },
      ])
      .select()

    if (err) throw err
    res.status(201).json(novo[0])
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// Atualizar status (PROTEGIDA)
app.patch('/atualizar-status/:id', verificarToken, async (req, res) => {
  const { id } = req.params
  const { novo_status } = req.body
  try {
    const { data, error } = await supabase
      .from('agendamentos')
      .update({ status_agendamento: novo_status })
      .eq('id_combina', id)
      .select()

    if (error) throw error
    res.json({ mensagem: 'Status atualizado!', agendamento: data[0] })
  } catch (error) {
    res.status(500).json({ erro: error.message })
  }
})

// -----------------------------------------------------------
// UTILITÁRIOS E INICIALIZAÇÃO
// -----------------------------------------------------------

app.get('/teste-conexao', async (req, res) => {
  try {
    const { count } = await supabase
      .from('categorias')
      .select('*', { count: 'exact', head: true })
    res.json({ status: 'Conectado! 🎉', total_categorias: count })
  } catch (err) {
    res.status(500).json({ erro: err.message })
  }
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando em http://localhost:${PORT}`)
})
