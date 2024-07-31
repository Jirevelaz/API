const Reportes = require('../models/reportes');

exports.createReportes = async (req, res) => {
    const { id_usuario, id_equipo, id_usuario_tecnico, descripcion_problema, solucion_problema, estatus, fecha } = req.body;
    try {
        const newReportes = new Reportes({ id_usuario, id_equipo, id_usuario_tecnico, descripcion_problema, solucion_problema, estatus, fecha });
        await newReportes.save();
        res.status(201).send('Reporte creado');
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

exports.getReportes = async (req, res) => {
    try {
        const reportes = await Reportes.find();
        res.status(200).json(reportes);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};
