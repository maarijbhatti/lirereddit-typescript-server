import argon2 from "argon2";
import { User } from "../entities/User";
import { MyContext } from "../typs";
import {
  Resolver,
  InputType,
  Field,
  Arg,
  Ctx,
  Mutation,
  ObjectType,
  Query,
} from "type-graphql";

@ObjectType()
class FieldError {
  @Field()
  field: string;

  @Field()
  message: string;
}

@ObjectType()
class UserResponse {
  @Field(() => [FieldError], { nullable: true })
  errors?: FieldError[];

  @Field(() => User, { nullable: true })
  user?: User;
}

@InputType()
class UsernamePasswordInput {
  @Field()
  username: string;

  @Field()
  password: string;
}

@Resolver()
export class UserResolver {
  @Mutation(() => UserResponse)
  async register(
    @Arg("options") options: UsernamePasswordInput,
    @Ctx() { em }: MyContext
  ): Promise<UserResponse> {
    if (options.username.length <= 2)
      return {
        errors: [
          {
            field: "username",
            message: "length must be greater then 2",
          },
        ],
      };

    if (options.password.length <= 3)
      return {
        errors: [
          {
            field: "password",
            message: "length must be greater then 3",
          },
        ],
      };

    const hashedPassword = await argon2.hash(options.password);
    const user = em.create(User, {
      username: options.username,
      password: hashedPassword,
    });
    try {
      await em.persistAndFlush(user);
      return { user };
    } catch (err) {
      console.log(err);
      if (err.code == "23505")
        return {
          errors: [
            {
              field: "username",
              message: "username already exist:",
            },
          ],
        };
      else
        return {
          errors: [
            {
              field: "username",
              message: err.detail,
            },
          ],
        };
    }
  }

  @Query(() => UserResponse)
  async login(
    @Arg("options") options: UsernamePasswordInput,
    @Ctx() { em }: MyContext
  ): Promise<UserResponse> {
    const user = await em.findOne(User, { username: options.username });

    if (!user) {
      return {
        errors: [
          {
            field: "username",
            message: "username does not exist",
          },
        ],
      };
    }

    const valid = await argon2.verify(user.password, options.password);
    if (!valid) {
      return {
        errors: [
          {
            field: "password",
            message: "incorrect password",
          },
        ],
      };
    }
    return {
      user,
    };
  }
}
