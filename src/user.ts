import { Definition, Property, Id, Skip, ObjectId } from 'dryerjs';

@Definition()
export class User {
  @Id()
  id: ObjectId;

  @Property()
  email: string;

  @Property({ update: Skip, output: Skip })
  password: string;

  @Property()
  name: string;
}
