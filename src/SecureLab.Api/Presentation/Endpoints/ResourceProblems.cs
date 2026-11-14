namespace SecureLab.Api.Presentation.Endpoints;

public static class ResourceProblems
{
    public static IResult NotFound(string title) =>
        Results.Problem(title: title, statusCode: StatusCodes.Status404NotFound);

    public static IResult Forbidden() =>
        Results.Problem(title: "Доступ заборонено", statusCode: StatusCodes.Status403Forbidden);

    public static IResult Conflict(string detail) =>
        Results.Problem(title: "Дія неможлива", detail: detail, statusCode: StatusCodes.Status409Conflict);
}