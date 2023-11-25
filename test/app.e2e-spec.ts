import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import * as mongoose from 'mongoose';
import { AppModule } from './../src/app.module';

export const isNil = (value: any): value is null | undefined =>
  value === null || value === undefined;

export const defaultTo = <T>(
  value: T | null | undefined,
  defaultValue: T,
): T => {
  const shouldUseDefaultValue =
    isNil(value) || (typeof value === 'number' && isNaN(value));
  return shouldUseDefaultValue ? defaultValue : (value as T);
};

export const isString = (value: any): value is string =>
  typeof value === 'string';

class TestHelper {
  constructor(public app: INestApplication) {}

  public async makeSuccessRequest(input: {
    query: string;
    variables?: object;
    headers?: Record<string, string>;
  }) {
    const requestObject = request(this.app.getHttpServer()).post('/graphql');
    for (const key in defaultTo(input.headers, {})) {
      requestObject.set(key, input.headers![key] as string);
    }
    const { body } = await requestObject.send(input);
    expect(body.errors).toBeUndefined();
    return body.data;
  }

  public async makeFailRequest(input: {
    query: string;
    variables?: object;
    headers?: Record<string, string>;
    errorMessageMustContains?: string;
  }) {
    const requestObject = request(this.app.getHttpServer()).post('/graphql');

    for (const key in defaultTo(input.headers, {})) {
      requestObject.set(key, input.headers![key] as string);
    }
    const {
      body: { errors },
    } = await requestObject.send({
      ...input,
      errorMessageMustContains: undefined,
    });
    expect(errors).toBeTruthy();

    if (isString(input.errorMessageMustContains)) {
      expect(errors[0].message).toContain(input.errorMessageMustContains);
    }
    return errors;
  }
}

describe('App works', () => {
  let testHelper: TestHelper;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    const app = moduleFixture.createNestApplication();
    await app.init();
    testHelper = new TestHelper(app);
  });

  afterEach(async () => {
    for (const connection of mongoose.connections) {
      await connection.close();
    }
  });

  afterAll(async () => {
    for (const connection of mongoose.connections) {
      await connection.close();
    }
  });

  it('Test', async () => {
    await testHelper.makeSuccessRequest({
      query: `
        query PaginatedPost {
          paginatePosts {
            docs {
              id
              isPublic
              content
            }
          }
        }
      `,
    });
  });
});
