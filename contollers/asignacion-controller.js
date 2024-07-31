const asignacion = require('../models/asignacion');

exports.createAsignacion = async (req, res) => {
    const { id_persona, id_equipo, marca, modelo, color, descripcion, memoria, disco_duro, procesador } = req.body;
    try {
        const newasignacion = new Asignacion({ id_persona, id_equipo, marca, modelo, color, descripcion, memoria, disco_duro, procesador });
        await newasignacion.save();
        res.status(201).send('Asignación creada');
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

exports.getAsignacion = async (req, res) => {
    try {
        const asignaciones = await asignacion.find();
        res.status(200).json(asignaciones);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};
