const express = require('express');
const router = express.Router();
const reportesControllers = require('../contollers/reportes-controller');

router.get('/', reportesControllers.getReportes);
router.post('/', reportesControllers.createReportes);

module.exports = router;
