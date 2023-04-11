//jshint esversion:6
const express = require('express')
const ejs = require('ejs')
const mongoose = require('mongoose')
const {
    Schema
} = mongoose
const {
    urlencoded
} = require('body-parser')
const encrypt = require('mongoose-encryption')
require('dotenv').config()

const port = 3000
const app = express()
app.use(express.json())
app.use(express.urlencoded({
    extended: true
}))
app.use(express.static('public'))
app.set('view engine', 'ejs')

mongoose.connect('mongodb://127.0.0.1:27017/userDB')

const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        index: {
            unique: true
        }
    },
    password: {
        type: String,
        required: true
    }
})

const secretKey = process.env.SECRET_KEY
userSchema.plugin(encrypt, {
    secret: secretKey,
    encryptedFields: ['password']
})

const User = new mongoose.model('User', userSchema)

app.get('/', (req, res) => {
    res.render('home')
})

app.get('/login', (req, res) => {
    res.render('login')
})

app.get('/register', (req, res) => {
    res.render('register')
})

app.post('/register', (req, res) => {
    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    })

    newUser.save().then((docs, err) => {
        if (!err) {
            res.render('secrets')
        } else {
            console.log(err)
        }
    })
})

app.post('/login', (req, res) => {
    const email = req.body.username
    const password = req.body.password

    User.findOne({
        email: email
    }).then((docs, err) => {
        if (!err) {
            if (docs === null) {
                res.send('Username or Password Invalid!!!')
                console.log(req.body)
            } else if (password === docs.password) {
                res.render('secrets')
                console.log(req.body)
            }

        } else {
            res.send('Username or Password Invalid!!!')
            console.log(req.body)
        }
    })
})

app.get('/logout', (req, res) => {
    res.redirect('/')
})

app.listen(port, (req, res) => {
    console.log(`Server running at port ${port}`)
})