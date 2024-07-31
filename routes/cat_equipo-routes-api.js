const express = require('express');
const router = express.Router();
const catEquipoControllers = require('../contollers/cat_equipo-controller');

router.get('/', catEquipoControllers.getCatEquipo);
router.post('/', catEquipoControllers.createCatEquipo);

module.exports = router;
