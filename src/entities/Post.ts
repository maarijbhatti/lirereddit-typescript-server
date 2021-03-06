import { Entity, PrimaryKey, Property } from "@mikro-orm/core";
import { Field, ObjectType } from "type-graphql";

@Entity()
@ObjectType()
export class Post {

  @Field()
  @PrimaryKey()
  _id!: number;

  @Field(()=>String)
  @Property({type:"date"})
  createdAt = new Date();

  @Field(()=>String)
  @Property({type:'date', onUpdate: () => new Date() })
  updatedAt = new Date();

  @Field()
  @Property({type:'text'})
  title!: string;

}