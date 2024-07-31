const express = require('express');
const router = express.Router();
const asignacionController = require('../contollers/asignacion-controller');

router.get('/', asignacionController.getAsignacion);
router.post('/', asignacionController.createAsignacion);

module.exports = router;
