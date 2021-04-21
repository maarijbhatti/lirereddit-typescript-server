import { UsernamePasswordInput } from "src/resolvers/UsernamePasswordInput";

export const validateRegister = (options: UsernamePasswordInput) => {
  if (!options.email.includes("@"))
    return [
      {
        field: "email",
        message: "Invalid email",
      },
    ];

  if (options.username.includes("@"))
    return [
      {
        field: "username",
        message: "cannot include @ sign",
      },
    ];

  if (options.username.length <= 2)
    return [
      {
        field: "username",
        message: "length must be greater then 2",
      },
    ];

  if (options.password.length <= 3)
    return [
      {
        field: "password",
        message: "length must be greater then 3",
      },
    ];

  return null;
};
