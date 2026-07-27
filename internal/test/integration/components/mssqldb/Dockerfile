FROM mcr.microsoft.com/mssql/server@sha256:49b45a911dc535e9345fbfd7101a1bd8a1e190a5f29b877ef75387a061e5fcf0

USER root

# Create a directory for our initialization
COPY setup.sql /setup.sql
RUN chown mssql /setup.sql

# Set required environment variables for the build-time run
ENV ACCEPT_EULA=Y
ENV MSSQL_SA_PASSWORD=p_ssW0rd

# Switch to mssql user for the initialization run
USER mssql

# Start SQL Server, wait for it to be ready, run the setup script, and then shut down.
RUN /opt/mssql/bin/sqlservr & \
    bash -c "until /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P \"$MSSQL_SA_PASSWORD\" -C -Q 'SELECT 1' &> /dev/null; do sleep 2; echo 'Waiting for SQL Server...'; done" && \
    /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -C -i /setup.sql && \
    pkill sqlservr && \
    sleep 5

# Use the default entrypoint
ENTRYPOINT ["/opt/mssql/bin/sqlservr"]