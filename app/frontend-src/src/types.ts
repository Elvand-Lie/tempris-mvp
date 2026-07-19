export type User = {
  email: string;
  name?: string;
  role: string;
  tenant_id?: string;
};

export type LoginResponse = {
  access_token: string;
  token_type: string;
  user: User;
};

export type ApiErrorShape = {
  status: number;
  message: string;
};
