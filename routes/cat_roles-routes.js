const express = require('express');
const router = express.Router();
const catRolesControllers = require('../contollers/cat_roles-controller');

router.get('/', catRolesControllers.getCatRoles);
router.post('/', catRolesControllers.createCatRoles);

module.exports = router;
