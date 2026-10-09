export interface paths {
  "/api/v1/readyz": {
    get: {
      responses: {
        200: {
          content: {
            "application/json": {
              status: string;
            };
          };
        };
      };
    };
  };
}
