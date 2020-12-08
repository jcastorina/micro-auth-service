require("dotenv").config();

const Sequelize = require("sequelize");
const postGresUsr = process.env.DB_USER;
const postGresPw = process.env.DB_PASS;
const host = process.env.DB_HOST;

const sequelize = new Sequelize(postGresUsr, postGresUsr, postGresPw, {
  host: host,
  dialect: "postgres",

  pool: {
    max: 5,
    min: 0,
    idle: 10000,
  },
});

const Credentials = sequelize.define(
  "credentials",
  {
    id: {
      type: Sequelize.STRING,
      field: "id",
      primaryKey: true,
    },
    hash: {
      type: Sequelize.STRING,
      field: "hash",
    },
    salt: {
      type: Sequelize.STRING,
      field: "salt",
    },
  },
  {
    freezeTableName: true,
  }
);

module.exports = { Credentials };
