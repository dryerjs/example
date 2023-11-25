import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import * as mongoose from 'mongoose';
import { AppModule } from './../src/app.module';
import { getModelToken } from '@nestjs/mongoose';

jest.setTimeout(10000);

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

  public async cleanDatabase() {
    await Promise.all(
      ['User', 'Post'].map(async (name) => {
        const model = this.app.get(getModelToken(name), {
          strict: false,
        }) as mongoose.Model<any>;
        await model.deleteMany({});
        await model.ensureIndexes({});
      }),
    );
  }

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

  public async getAccessToken(email: string) {
    const { signIn } = await this.makeSuccessRequest({
      query: `
        mutation {
          signIn(input: {
            email: "${email}"
            password: "password"
          }) {
            accessToken
          }
        }
      `,
    });

    return `Bearer ${signIn.accessToken}`;
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
    await testHelper.cleanDatabase();
  });

  afterAll(async () => {
    for (const connection of mongoose.connections) {
      await connection.close();
    }
  });

  const ADMIN_EMAIL = 'admin@dryerjs.com';
  const USER_1_EMAIL = 'user@dryerjs.com';
  const USER_2_EMAIL = 'secondUser@dryerjs.com';

  it('Admin can get all posts', async () => {
    const result = await testHelper.makeSuccessRequest({
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
      headers: {
        Authorization: await testHelper.getAccessToken(ADMIN_EMAIL),
      },
    });

    expect(
      result.paginatePosts.docs.sort((a, b) => {
        if (a.id === b.id) return 0;
        if (a.id > b.id) return 1;
        return -1;
      }),
    ).toEqual([
      {
        id: '000000000000000000000002',
        isPublic: true,
        content: 'Admin public announcement',
      },
      {
        id: '000000000000000000000003',
        isPublic: false,
        content: 'Admin private note',
      },
      {
        id: '000000000000000000000004',
        isPublic: true,
        content: 'User public note',
      },
      {
        id: '000000000000000000000005',
        isPublic: false,
        content: 'User private note',
      },
      {
        id: '000000000000000000000006',
        isPublic: true,
        content: 'Second user public note',
      },
      {
        id: '000000000000000000000007',
        isPublic: false,
        content: 'Second user private note',
      },
    ]);
  });

  it('User can get only public post and his own posts', async () => {
    const result = await testHelper.makeSuccessRequest({
      query: `
        query PaginatedPost {
          paginatePosts {
            docs {
              id
              isPublic
              content
              userId
            }
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(USER_1_EMAIL),
      },
    });

    expect(
      result.paginatePosts.docs.sort((a, b) => {
        if (a.id === b.id) return 0;
        if (a.id > b.id) return 1;
        return -1;
      }),
    ).toEqual([
      {
        id: '000000000000000000000002',
        isPublic: true,
        content: 'Admin public announcement',
        userId: '000000000000000000000000',
      },
      {
        id: '000000000000000000000004',
        isPublic: true,
        content: 'User public note',
        userId: '000000000000000000000001',
      },
      {
        id: '000000000000000000000005',
        isPublic: false,
        content: 'User private note',
        userId: '000000000000000000000001',
      },
      {
        id: '000000000000000000000006',
        isPublic: true,
        content: 'Second user public note',
        userId: '000000000000000000000002',
      },
    ]);
  });
});
