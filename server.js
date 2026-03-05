// Module imports
require('dotenv').config()
const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

// The greater the number, the harder the password is to crack
const saltRounds = 10
const testHash = "$2b$10$Nqel0GJ1M0WKBTqmmTXvreL2UpFe1OdOQtok45gRa7Cx3m6MRZOh6"

// Lets us send json with express
app.use(express.json())

// Landing Page
app.get('/', (req, res) => {
    return res.send('<h1>Hello World</h1>')
})

// Takes username and password, hashes password and returns username + hash for testing
app.post('/signup', (req, res) => {
    const username = req.body.username
    const password = req.body.password

    // bcrypt module hash function
    bcrypt.hash(password, saltRounds, function(err, hash) {
        if (err) return res.sendStatus(500)
        // STORE IN DB IN PROD, NEVER STORE PLAIN TEXT PASSWORDS 
        res.json({username, hash})
    })
})

// Takes username and password, compares password to hash in db
// serializes user into payload to sign jwt, returns token
app.post('/login', (req, res) => {
    const username = req.body.username
    const password = req.body.password

    const user = {name : username}

    // COMPARE PASSWORD TO THE HASH FROM DB 
    // TODO: Compare req.password to hash in db with bcrypt.compare
    //       If match == True, issue access Token and return it 
    //       Need to inject ACCESS_TOKEN_SECRET from .env 

    // Check if user is who they say they are
    // Will attach json webtoken to user
    // Async to wait on bcrypt function
    async function comparePassword(user, password) {
        // Bool that returns from bcrypt
        // Compare password to hash in database
        const match = await bcrypt.compare(password, testHash);

        // Check match
        // If True
        if (match) {
            // If match, generate access token
            const accessToken = generateAccessToken(user);
            // Also want a refresh token
            // Injecting into .env file under REFRESH_TOKEN_SECRET
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);

            return res.json({accessToken:accessToken, refreshToken:refreshToken})
        }
        
        // If false
        return res.sendStatus(403) // return forbidden
    }

    return comparePassword(user, password)
})

// Purpose is to protect endpoints to prevent unwanted access
app.post('/token', (req,response) => {
    const refreshToken = req.body.token

    // Check refresh token
    if (refreshToken === null) return res.sendStatus(401) // unauthorized

    // Verify signed token (from .env file)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {

        // If not signed, return access denied
        if (err) return res.status(403).send('Failed to verify')

        // Otherwise new access token
        const accessToken = generateAccessToken({name:user.name})
        res.json({accessToken:accessToken})
    })
})

// We're using 8980 for localhost
app.listen(8980, (error) => {
    if (error) return console.log(`Server failed to start ${error}`)
    console.log("Server is listening")
})

// Generates random string
function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '5m'})
}