// This file is used to generate Prisma types
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
  try {
    // Just test the connection
    await prisma.$connect();
    console.log('Database connected successfully');
    await prisma.$disconnect();
  } catch (error) {
    console.error('Database connection error:', error.message);
    process.exit(1);
  }
}

main();
