const CatRoles = require('../models/cat_roles');

exports.createCatRoles = async (req, res) => {
    const { nombre, descripcion } = req.body;
    try {
        const newCatRoles = new CatRoles({ nombre, descripcion });
        await newCatRoles.save();
        res.status(201).send('Catálogo de roles creado');
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

exports.getCatRoles = async (req, res) => {
    try {
        const roles = await CatRoles.find();
        res.status(200).json(roles);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};
