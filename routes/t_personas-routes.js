const express = require('express');
const router = express.Router();
const personaControllers = require('../contollers/t_personas-controller');

router.get('/', personaControllers.getPersona);
router.post('/', personaControllers.createPersona);

module.exports = router;
