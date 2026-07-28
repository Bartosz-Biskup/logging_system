class RepositoryException(Exception):
    ...


class ObjectAlreadyExists(RepositoryException):
    ...


class ObjectNotFoundException(RepositoryException):
    ...