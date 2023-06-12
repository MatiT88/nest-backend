import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";

@Schema()
export class User {
    //id: string , esto lo crea Mongo automaticamente

    @Prop({ unique: true, required: true})
    email: string;

    @Prop({required: true})
    name: string;

    @Prop({minlength: 6, required: true})
    password: string;

    @Prop({default: true})
    isActive: boolean;

    @Prop({type: [String], default: ['user']})
    roles: string[];
}

export const UserSchema = SchemaFactory.createForClass(User);
