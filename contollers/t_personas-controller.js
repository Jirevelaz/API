const Persona = require('../models/t_persona');

exports.createPersona = async (req, res) => {
    const { paterno, materno, nombre, fecha_nacimiento, sexo, telefono, correo, fechaInsert } = req.body;
    try {
        const newPersona = new Persona({ paterno, materno, nombre, fecha_nacimiento, sexo, telefono, correo, fechaInsert });
        await newPersona.save();
        res.status(201).send('Persona creada');
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

exports.getPersona = async (req, res) => {
    try {
        const personas = await Persona.find();
        res.status(200).json(personas);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};
