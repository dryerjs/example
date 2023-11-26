import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import * as mongoose from 'mongoose';
import { AppModule, SeederService } from './../src/app.module';
import { getModelToken } from '@nestjs/mongoose';

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

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    const app = moduleFixture.createNestApplication();
    await app.init();
    testHelper = new TestHelper(app);
  });

  beforeEach(async () => {
    await testHelper.app.get(SeederService).onModuleInit();
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
        id: '000000000000000000000003',
        isPublic: true,
        content: 'Admin public announcement',
      },
      {
        id: '000000000000000000000004',
        isPublic: false,
        content: 'Admin private note',
      },
      {
        id: '000000000000000000000005',
        isPublic: true,
        content: 'User public note',
      },
      {
        id: '000000000000000000000006',
        isPublic: false,
        content: 'User private note',
      },
      {
        id: '000000000000000000000007',
        isPublic: true,
        content: 'Second user public note',
      },
      {
        id: '000000000000000000000008',
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
        id: '000000000000000000000003',
        isPublic: true,
        content: 'Admin public announcement',
        userId: '000000000000000000000000',
      },
      {
        id: '000000000000000000000005',
        isPublic: true,
        content: 'User public note',
        userId: '000000000000000000000001',
      },
      {
        id: '000000000000000000000006',
        isPublic: false,
        content: 'User private note',
        userId: '000000000000000000000001',
      },
      {
        id: '000000000000000000000007',
        isPublic: true,
        content: 'Second user public note',
        userId: '000000000000000000000002',
      },
    ]);
  });

  it('Admin can get one private post of other user', async () => {
    const result = await testHelper.makeSuccessRequest({
      query: `
        query {
          post(id: "000000000000000000000006") {
            id
            isPublic
            content
            userId
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(ADMIN_EMAIL),
      },
    });

    expect(result.post.id).toEqual('000000000000000000000006');
  });

  it('User can get one private post his own', async () => {
    const result = await testHelper.makeSuccessRequest({
      query: `
        query {
          post(id: "000000000000000000000008") {
            id
            isPublic
            content
            userId
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(USER_2_EMAIL),
      },
    });

    expect(result.post.id).toEqual('000000000000000000000008');
  });

  it('User can get one public post his own', async () => {
    const result = await testHelper.makeSuccessRequest({
      query: `
        query {
          post(id: "000000000000000000000007") {
            id
            isPublic
            content
            userId
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(USER_2_EMAIL),
      },
    });

    expect(result.post.id).toEqual('000000000000000000000007');
  });

  it('User can get one public post of other', async () => {
    const result = await testHelper.makeSuccessRequest({
      query: `
        query {
          post(id: "000000000000000000000005") {
            id
            isPublic
            content
            userId
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(USER_2_EMAIL),
      },
    });

    expect(result.post.id).toEqual('000000000000000000000005');
  });

  it('User cannot get private post of other', async () => {
    await testHelper.makeFailRequest({
      query: `
        query {
          post(id: "000000000000000000000006") {
            id
            isPublic
            content
            userId
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(USER_2_EMAIL),
      },
      errorMessageMustContains: 'No Post found with ID',
    });
  });

  it('Guess can get public posts', async () => {
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
    });

    expect(
      result.paginatePosts.docs.sort((a, b) => {
        if (a.id === b.id) return 0;
        if (a.id > b.id) return 1;
        return -1;
      }),
    ).toEqual([
      {
        id: '000000000000000000000003',
        isPublic: true,
        content: 'Admin public announcement',
      },
      {
        id: '000000000000000000000005',
        isPublic: true,
        content: 'User public note',
      },
      {
        id: '000000000000000000000007',
        isPublic: true,
        content: 'Second user public note',
      },
    ]);
  });

  it('Guess can get public post', async () => {
    const result = await testHelper.makeSuccessRequest({
      query: `
        query {
          post(id: "000000000000000000000003") {
            id
            isPublic
            content
            userId
          }
        }
      `,
    });

    expect(result.post.id).toEqual('000000000000000000000003');
  });

  it('Guess cannot get private post', async () => {
    await testHelper.makeFailRequest({
      query: `
        query {
          post(id: "000000000000000000000006") {
            id
            isPublic
            content
            userId
          }
        }
      `,
      errorMessageMustContains: 'No Post found with ID',
    });
  });

  it('User can update his own post', async () => {
    const result = await testHelper.makeSuccessRequest({
      query: `
        mutation {
          updatePost(input: {
            id: "000000000000000000000006"
            content: "Updated content"
          }) {
            id
            isPublic
            content
            userId
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(USER_1_EMAIL),
      },
    });

    expect(result.updatePost.content).toEqual('Updated content');
  });

  it('User cannot update other post', async () => {
    await testHelper.makeFailRequest({
      query: `
        mutation {
          updatePost(input: {
            id: "000000000000000000000006"
            content: "Updated content"
          }) {
            id
            isPublic
            content
            userId
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(USER_2_EMAIL),
      },
      errorMessageMustContains: 'No Post found with ID',
    });
  });

  it('Admin can update other post', async () => {
    const result = await testHelper.makeSuccessRequest({
      query: `
        mutation {
          updatePost(input: {
            id: "000000000000000000000006"
            content: "Updated content"
          }) {
            id
            isPublic
            content
            userId
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(ADMIN_EMAIL),
      },
    });

    expect(result.updatePost.content).toEqual('Updated content');
  });

  it('User can remove his own post', async () => {
    await testHelper.makeSuccessRequest({
      query: `
        mutation {
          removePost(id: "000000000000000000000006") {
            success
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(USER_1_EMAIL),
      },
    });
  });

  it('User cannot remove other post', async () => {
    await testHelper.makeFailRequest({
      query: `
        mutation {
          removePost(id: "000000000000000000000006") {
            success
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(USER_2_EMAIL),
      },
      errorMessageMustContains: 'No Post found with ID',
    });
  });

  it('Admin can remove other post', async () => {
    await testHelper.makeSuccessRequest({
      query: `
        mutation {
          removePost(id: "000000000000000000000006") {
            success
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(ADMIN_EMAIL),
      },
    });
  });

  it('User cannot update other user', async () => {
    await testHelper.makeFailRequest({
      query: `
        mutation {
          updateUser(input: {
            id: "000000000000000000000002"
            name: "Updated name"
          }) {
            id
            name
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(USER_1_EMAIL),
      },
      errorMessageMustContains: 'Cannot update other user',
    });
  });

  it('User cannot update other user role', async () => {
    await testHelper.makeFailRequest({
      query: `
        mutation {
          updateUser(input: {
            id: "000000000000000000000001"
            role: "ADMIN"
          }) {
            id
            name
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(USER_1_EMAIL),
      },
      errorMessageMustContains: 'Cannot update role',
    });
  });

  it('User cannot remove user', async () => {
    await testHelper.makeFailRequest({
      query: `
        mutation {
          removeUser(id: "000000000000000000000002") {
            success
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(USER_1_EMAIL),
      },
      errorMessageMustContains: 'AdminOnly',
    });
  });

  it('Admin can remove user', async () => {
    await testHelper.makeSuccessRequest({
      query: `
        mutation {
          removeUser(id: "000000000000000000000002") {
            success
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(ADMIN_EMAIL),
      },
    });
  });

  it('Admin can update user role', async () => {
    const result = await testHelper.makeSuccessRequest({
      query: `
        mutation {
          updateUser(input: {
            id: "000000000000000000000001"
            role: "ADMIN"
          }) {
            id
            role
          }
        }
      `,
      headers: {
        Authorization: await testHelper.getAccessToken(ADMIN_EMAIL),
      },
    });

    expect(result.updateUser.role).toEqual('ADMIN');
  });
});
