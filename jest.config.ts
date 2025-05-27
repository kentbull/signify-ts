import { Config } from 'jest';

const config: Config = {
    preset: 'ts-jest',
    testMatch: ['<rootDir>/test/**/*.test.ts'],
    projects: ['<rootDir>', '<rootDir>/examples/integration-scripts'],
    setupFilesAfterEnv: ['jest-expect-message']
};

export default config;
