const CatEquipo = require('../models/cat_equipo');

exports.createCatEquipo = async (req, res) => {
    const { nombre, descripcion } = req.body;
    try {
        const newCatEquipo = new CatEquipo({ nombre, descripcion });
        await newCatEquipo.save();
        res.status(201).send('Catálogo de equipo creado');
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

exports.getCatEquipo = async (req, res) => {
    try {
        const equipos = await CatEquipo.find();
        res.status(200).json(equipos);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};
