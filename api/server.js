const express = require("express");
const bcrypt = require("bcryptjs")

const server = express();
const Users = require("../helpers/helpers.js")
const {
    validateBody,
    validateUniqueUsername
} = require("../middleware/validate.js")

server.use(express.json());

server.get("/",(req,res) => {
    res.status(200).json({message: "up"})
})

server.post("/api/register",
validateBody,
validateUniqueUsername,
async(req,res) => {
    const {body} = req
    const hash = bcrypt.hashSync(body.password, 12)
    body.password = hash
    try {
        const response = await Users.createUser(body);
        if (response) {
            res.status(201).json(response)
        }
        else {
            res.status(400).json({message: "User could not be created"})
        }
    } catch (error) {
        res.status(500).json(error)
    }
})

server.post("/api/login",validateBody,async(req,res) => {
    const {body} = req
    try {
        const user = await Users.login({username: body.username})
        if (user) {
            const auth = bcrypt.compareSync(body.password, user.password)
            if (auth) {
                res.status(200).json({message: `Welcome ${user.username}!`})
            }
            else {
                res.status(401).json({message: "Invalid credentials"})
            }
        }
        else {
            res.status(400).json({message: "Could not find user"})
        }
    } catch (error) {
        res.status(500).json(error)
    }

})
module.exports = server;

