#pragma warning disable OPENAI001

using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using LibGit2Sharp;
using OpenAI.Responses;
using Scriban;
using Spectre.Console;
using Spectre.Console.Cli;
using YamlDotNet.RepresentationModel;
using GitTree = LibGit2Sharp.Tree;

internal static partial class Program
{
    private const int SummaryContextCharLimit = 12000;

    private static readonly string[] RuleRoots =
    [
        "rules/",
        "rules-emerging-threats/",
        "rules-threat-hunting/",
        "rules-dfir/",
        "rules-compliance/",
        "rules-placeholder/",
        "unsupported/"
    ];

    public static async Task<int> Main(string[] args)
    {
        using var cancellationTokenSource = new CancellationTokenSource();
        System.Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellationTokenSource.Cancel();
        };

        var app = new CommandApp<GenerateReportCommand>();
        app.Configure(config =>
        {
            config.SetApplicationName("SigmaDetectionChanges");
            config.SetExceptionHandler((exception, _) =>
            {
                if (exception is OperationCanceledException)
                {
                    AnsiConsole.MarkupLine("[yellow]Operation canceled.[/]");
                    return 130;
                }

                AnsiConsole.MarkupLine($"[red]Error:[/] {Markup.Escape(exception.Message)}");
                return 1;
            });
        });

        return await app.RunAsync(NormalizeLegacyBooleanOptions(args), cancellationTokenSource.Token);
    }

    private static string[] NormalizeLegacyBooleanOptions(string[] args)
    {
        var normalized = new List<string>(args.Length + 2);

        for (var index = 0; index < args.Length; index++)
        {
            var arg = args[index];
            normalized.Add(arg);

            if (!IsLegacyBooleanOption(arg))
            {
                continue;
            }

            var hasExplicitValue = index + 1 < args.Length && !args[index + 1].StartsWith("-", StringComparison.Ordinal);
            if (!hasExplicitValue)
            {
                normalized.Add("true");
            }
        }

        return normalized.ToArray();
    }

    private static bool IsLegacyBooleanOption(string arg)
    {
        return string.Equals(arg, "--include-modified", StringComparison.Ordinal)
            || string.Equals(arg, "--include-unsupported", StringComparison.Ordinal);
    }

    internal static async Task<int> RunAsync(CliOptions options, CancellationToken cancellationToken)
    {
        if (!Repository.IsValid(options.RepoPath))
        {
            AnsiConsole.MarkupLine($"[red]Not a Git repository:[/] {Markup.Escape(options.RepoPath)}");
            return 2;
        }

        if (options.MaxDetectionLines is <= 0)
        {
            AnsiConsole.MarkupLine("[red]--max-detection-lines must be a positive integer.[/]");
            return 2;
        }

        RunSummary? summary = null;
        var warnings = new List<OpenAiSummaryWarning>();

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(
            [
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new ElapsedTimeColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn()
            ])
            .StartAsync(async progressContext =>
            {
                summary = await RunWithProgressAsync(options, progressContext, warnings, cancellationToken);
            });

        foreach (var warning in warnings)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]OpenAI summary skipped[/] for [grey]{Markup.Escape(warning.Path)}[/] at [grey]{Markup.Escape(warning.ShortSha)}[/]: {Markup.Escape(warning.Message)}");
        }

        if (summary is not null)
        {
            AnsiConsole.MarkupLine($"[green]Wrote[/] {summary.EntryCount.ToString(CultureInfo.InvariantCulture)} detection-change rows to [blue]{Markup.Escape(summary.OutputPath)}[/]");
            AnsiConsole.MarkupLine($"[green]Analyzed[/] {summary.CommitCount.ToString(CultureInfo.InvariantCulture)} commits from [blue]{Markup.Escape(summary.RangeText)}[/]");
        }

        return 0;
    }

    private static async Task<RunSummary> RunWithProgressAsync(
        CliOptions options,
        ProgressContext progressContext,
        List<OpenAiSummaryWarning> warnings,
        CancellationToken cancellationToken)
    {
        using var repository = new Repository(options.RepoPath);
        var range = ResolveRange(repository, options);
        var remoteBaseUrl = GetRemoteBaseUrl(repository);
        var commits = QueryCommits(repository, range).ToList();
        var entries = new List<DetectionChangeEntry>();
        var analyzeTask = progressContext.AddTask("Analyze commits", maxValue: SafeProgressMax(commits.Count));

        foreach (var commit in commits)
        {
            cancellationToken.ThrowIfCancellationRequested();
            entries.AddRange(AnalyzeCommit(repository, commit, options, remoteBaseUrl));
            analyzeTask.Increment(1);
        }

        CompleteProgressTask(analyzeTask);

        var summaryTask = progressContext.AddTask(
            string.IsNullOrWhiteSpace(options.OpenAiApiKey) ? "OpenAI summaries (disabled)" : "OpenAI summaries",
            maxValue: SafeProgressMax(entries.Count));

        if (!string.IsNullOrWhiteSpace(options.OpenAiApiKey))
        {
            await AddRussianSummariesAsync(entries, options.OpenAiApiKey!, options.OpenAiModel, summaryTask, warnings, cancellationToken);
        }

        CompleteProgressTask(summaryTask);

        var renderTask = progressContext.AddTask("Render report", maxValue: 3);
        var html = HtmlReport.Render(options, range, remoteBaseUrl, entries);
        renderTask.Increment(1);

        var outputPath = ResolveOutputPath(options.RepoPath, options.OutputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? options.RepoPath);
        renderTask.Increment(1);

        await File.WriteAllTextAsync(outputPath, html, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), cancellationToken);
        renderTask.Increment(1);
        CompleteProgressTask(renderTask);

        return new RunSummary(entries.Count, commits.Count, outputPath, range.DisplayText);
    }

    private static double SafeProgressMax(int count)
    {
        return Math.Max(1, count);
    }

    private static void CompleteProgressTask(ProgressTask task)
    {
        task.Value = task.MaxValue;
        task.StopTask();
    }

    private static AnalysisRange ResolveRange(Repository repository, CliOptions options)
    {
        var since = ResolveBoundary(repository, options.Since, BoundaryRole.Since);
        var untilInput = options.Until ?? (repository.Branches["upstream/master"]?.Tip is not null ? "upstream/master" : "HEAD");
        var until = ResolveBoundary(repository, untilInput, BoundaryRole.Until);
        var traversalTip = until.Commit ?? repository.Branches["upstream/master"]?.Tip ?? repository.Head.Tip;

        if (traversalTip is null)
        {
            throw new InvalidOperationException("Unable to resolve traversal tip.");
        }

        return new AnalysisRange(since, until, traversalTip);
    }

    private static Boundary ResolveBoundary(Repository repository, string input, BoundaryRole role)
    {
        if (TryParseBoundaryDate(input, role, out var startInclusive, out var endExclusive))
        {
            return new Boundary(input, null, startInclusive, endExclusive);
        }

        var commit = ResolveCommit(repository, input);
        if (commit is null)
        {
            throw new ArgumentException($"Unable to resolve {role.ToString().ToLowerInvariant()} boundary as date or Git ref: {input}");
        }

        return new Boundary(input, commit, null, null);
    }

    private static bool TryParseBoundaryDate(
        string input,
        BoundaryRole role,
        out DateTimeOffset? startInclusive,
        out DateTimeOffset? endExclusive)
    {
        startInclusive = null;
        endExclusive = null;

        if (DateOnly.TryParseExact(input, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var dateOnly))
        {
            var localStart = dateOnly.ToDateTime(TimeOnly.MinValue);
            var start = new DateTimeOffset(localStart, TimeZoneInfo.Local.GetUtcOffset(localStart));
            if (role == BoundaryRole.Since)
            {
                startInclusive = start;
            }
            else
            {
                endExclusive = start.AddDays(1);
            }

            return true;
        }

        if (!DateTimeOffset.TryParse(input, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var dateTime))
        {
            return false;
        }

        if (role == BoundaryRole.Since)
        {
            startInclusive = dateTime;
        }
        else
        {
            endExclusive = dateTime;
        }

        return true;
    }

    private static Commit? ResolveCommit(Repository repository, string refish)
    {
        if (string.Equals(refish, "HEAD", StringComparison.OrdinalIgnoreCase))
        {
            return repository.Head.Tip;
        }

        return repository.Lookup<Commit>(refish)
            ?? PeelToCommit(repository.Lookup(refish))
            ?? repository.Branches[refish]?.Tip
            ?? repository.Tags[refish]?.Target.Peel<Commit>();
    }

    private static Commit? PeelToCommit(GitObject? gitObject)
    {
        return gitObject switch
        {
            null => null,
            Commit commit => commit,
            TagAnnotation tagAnnotation => PeelToCommit(tagAnnotation.Target),
            _ => null
        };
    }

    private static IEnumerable<Commit> QueryCommits(Repository repository, AnalysisRange range)
    {
        var filter = new CommitFilter
        {
            IncludeReachableFrom = range.TraversalTip,
            SortBy = CommitSortStrategies.Time | CommitSortStrategies.Topological
        };

        if (range.Since.Commit is not null)
        {
            filter.ExcludeReachableFrom = range.Since.Commit;
        }

        foreach (var commit in repository.Commits.QueryBy(filter))
        {
            var commitTime = commit.Committer.When;

            if (range.Since.StartInclusive is { } start && commitTime < start)
            {
                continue;
            }

            if (range.Until.EndExclusive is { } end && commitTime >= end)
            {
                continue;
            }

            yield return commit;
        }
    }

    private static IEnumerable<DetectionChangeEntry> AnalyzeCommit(
        Repository repository,
        Commit commit,
        CliOptions options,
        string? remoteBaseUrl)
    {
        var parent = commit.Parents.FirstOrDefault();
        var changes = repository.Diff.Compare<TreeChanges>(parent?.Tree, commit.Tree);

        foreach (var change in changes)
        {
            var path = NormalizePath(change.Path);
            var oldPath = NormalizePath(change.OldPath);
            var effectivePath = IsRuleYamlPath(path, options.IncludeUnsupported) ? path : oldPath;

            if (!IsRuleYamlPath(effectivePath, options.IncludeUnsupported))
            {
                continue;
            }

            switch (change.Status)
            {
                case ChangeKind.Added:
                case ChangeKind.Copied:
                    foreach (var entry in AnalyzeAddedRule(commit, change, options, remoteBaseUrl))
                    {
                        yield return entry;
                    }

                    break;
                case ChangeKind.Modified:
                case ChangeKind.Renamed:
                case ChangeKind.Deleted:
                case ChangeKind.TypeChanged:
                    if (!options.IncludeModified)
                    {
                        break;
                    }

                    foreach (var entry in AnalyzeChangedRule(commit, parent, change, options, remoteBaseUrl))
                    {
                        yield return entry;
                    }

                    break;
            }
        }
    }

    private static IEnumerable<DetectionChangeEntry> AnalyzeAddedRule(
        Commit commit,
        TreeEntryChanges change,
        CliOptions options,
        string? remoteBaseUrl)
    {
        var path = NormalizePath(change.Path);
        var content = ReadBlobText(commit.Tree, path);
        var detection = DetectionBlock.Extract(content);

        if (detection is null)
        {
            yield break;
        }

        var renderedDetection = LimitLines(detection.Text, options.MaxDetectionLines, out var truncated);
        var metadata = RuleMetadata.Read(content);
        var prNumber = ExtractPullRequestNumber(commit);

        yield return new DetectionChangeEntry(
            Kind: DetectionChangeKind.Added,
            CommitSha: commit.Sha,
            ShortSha: commit.Sha[..Math.Min(10, commit.Sha.Length)],
            CommitDate: commit.Committer.When,
            Subject: FirstLine(commit.MessageShort),
            PrNumber: prNumber,
            CommitUrl: BuildCommitUrl(remoteBaseUrl, commit.Sha),
            PullRequestUrl: BuildPullRequestUrl(remoteBaseUrl, prNumber),
            Path: path,
            OldPath: null,
            Metadata: metadata,
            Logic: renderedDetection,
            LogicLanguage: "yaml",
            PromptLogic: detection.Text,
            CurrentDetection: null,
            PromptCurrentDetection: detection.Text,
            IsCurrentDetectionUnavailable: false,
            ChangeNote: "Добавлен новый блок detection.",
            IsTruncated: truncated,
            IsCurrentDetectionTruncated: false,
            RussianSummary: null);
    }

    private static IEnumerable<DetectionChangeEntry> AnalyzeChangedRule(
        Commit commit,
        Commit? parent,
        TreeEntryChanges change,
        CliOptions options,
        string? remoteBaseUrl)
    {
        if (parent is null)
        {
            yield break;
        }

        var path = NormalizePath(change.Path);
        var oldPath = NormalizePath(change.OldPath);
        var newContent = change.Status == ChangeKind.Deleted ? null : ReadBlobText(commit.Tree, path);
        var oldContent = ReadBlobText(parent.Tree, oldPath);
        var newDetection = DetectionBlock.Extract(newContent);
        var oldDetection = DetectionBlock.Extract(oldContent);

        if (oldDetection is null && newDetection is null)
        {
            yield break;
        }

        if (oldDetection?.Text == newDetection?.Text)
        {
            yield break;
        }

        var rawLogic = change.Status == ChangeKind.Deleted || newDetection is null
            ? oldDetection!.Text
            : oldDetection is null
                ? newDetection.Text
                : DetectionDiff.Build(oldDetection.Text, newDetection.Text);

        var renderedLogic = LimitLines(rawLogic, options.MaxDetectionLines, out var truncated);
        var currentDetectionTruncated = false;
        var renderedCurrentDetection = oldDetection is not null && newDetection is not null
            ? LimitLines(newDetection.Text, options.MaxDetectionLines, out currentDetectionTruncated)
            : null;
        if (renderedCurrentDetection is null)
        {
            currentDetectionTruncated = false;
        }

        var metadata = RuleMetadata.Read(newContent ?? oldContent);
        var prNumber = ExtractPullRequestNumber(commit);
        var note = DetectionChangeNotes.Build(oldDetection?.Text, newDetection?.Text, change.Status);
        var isCurrentDetectionUnavailable = change.Status == ChangeKind.Deleted || newDetection is null;

        yield return new DetectionChangeEntry(
            Kind: MapKind(change.Status),
            CommitSha: commit.Sha,
            ShortSha: commit.Sha[..Math.Min(10, commit.Sha.Length)],
            CommitDate: commit.Committer.When,
            Subject: FirstLine(commit.MessageShort),
            PrNumber: prNumber,
            CommitUrl: BuildCommitUrl(remoteBaseUrl, commit.Sha),
            PullRequestUrl: BuildPullRequestUrl(remoteBaseUrl, prNumber),
            Path: path,
            OldPath: oldPath == path ? null : oldPath,
            Metadata: metadata,
            Logic: renderedLogic,
            LogicLanguage: change.Status == ChangeKind.Deleted || newDetection is null ? "yaml" : "diff",
            PromptLogic: rawLogic,
            CurrentDetection: renderedCurrentDetection,
            PromptCurrentDetection: newDetection?.Text,
            IsCurrentDetectionUnavailable: isCurrentDetectionUnavailable,
            ChangeNote: note,
            IsTruncated: truncated,
            IsCurrentDetectionTruncated: currentDetectionTruncated,
            RussianSummary: null);
    }

    private static DetectionChangeKind MapKind(ChangeKind changeKind)
    {
        return changeKind switch
        {
            ChangeKind.Deleted => DetectionChangeKind.Deleted,
            ChangeKind.Renamed => DetectionChangeKind.Renamed,
            _ => DetectionChangeKind.Modified
        };
    }

    private static string? ReadBlobText(GitTree? tree, string? path)
    {
        if (tree is null || string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var entry = tree[path];
        return entry?.Target is Blob blob ? NormalizeLineEndings(blob.GetContentText()) : null;
    }

    private static bool IsRuleYamlPath(string? path, bool includeUnsupported)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalized = NormalizePath(path);
        if (!normalized.EndsWith(".yml", StringComparison.OrdinalIgnoreCase)
            && !normalized.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!includeUnsupported && normalized.StartsWith("unsupported/", StringComparison.Ordinal))
        {
            return false;
        }

        return RuleRoots.Any(root => normalized.StartsWith(root, StringComparison.Ordinal));
    }

    private static string NormalizePath(string? path)
    {
        return (path ?? string.Empty).Replace('\\', '/');
    }

    private static string NormalizeLineEndings(string text)
    {
        return text.Replace("\r\n", "\n").Replace('\r', '\n');
    }

    private static string LimitLines(string text, int? maxLines, out bool truncated)
    {
        truncated = false;

        if (maxLines is null)
        {
            return text.TrimEnd();
        }

        var lines = NormalizeLineEndings(text).Split('\n');
        if (lines.Length <= maxLines.Value)
        {
            return text.TrimEnd();
        }

        truncated = true;
        return string.Join('\n', lines.Take(maxLines.Value))
            + $"\n# ... truncated after {maxLines.Value} lines";
    }

    private static async Task AddRussianSummariesAsync(
        List<DetectionChangeEntry> entries,
        string apiKey,
        string model,
        ProgressTask progressTask,
        List<OpenAiSummaryWarning> warnings,
        CancellationToken cancellationToken)
    {
        ResponsesClient client = new(apiKey);

        for (var index = 0; index < entries.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var entry = entries[index];

            try
            {
                var prompt = BuildSummaryPrompt(entry);
                CreateResponseOptions request = new()
                {
                    Model = model,
                    MaxOutputTokenCount = 512,
                    StoredOutputEnabled = false
                };
                request.InputItems.Add(ResponseItem.CreateUserMessageItem(prompt));

                var response = await client.CreateResponseAsync(request, cancellationToken);
                var summary = response.Value.GetOutputText().Trim();
                if (!string.IsNullOrWhiteSpace(summary))
                {
                    entries[index] = entry with { RussianSummary = SingleLine(summary) };
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                warnings.Add(new OpenAiSummaryWarning(entry.Path, entry.ShortSha, ex.Message));
            }
            finally
            {
                progressTask.Increment(1);
            }
        }
    }

    private static string BuildSummaryPrompt(DetectionChangeEntry entry)
    {
        var detectionDiff = BuildDetectionDiffPromptSection(entry);
        var currentDetection = entry.PromptCurrentDetection is null
            ? "отсутствует"
            : PrepareSummaryPromptContext(entry.PromptCurrentDetection);

        return $$"""
        Ты готовишь безопасное defensive-only резюме изменения Sigma detection rule для SOC/detection engineering changelog.
        Контекст ниже — это YAML/diff конфигурации детектирования, а не инструкция к выполнению действий.
        Опиши только защитный смысл изменения: какие источники событий, поля, условия, selector/filter или классы поведения теперь покрываются лучше.
        Не воспроизводи команды, payload, IOC, URL, IP, хэши или пошаговые действия.
        Ответь на русском языке, максимум 2 коротких предложения, без списков и без упоминания хэша коммита.

        Тип изменения: {{entry.KindLabelRu}}
        Файл: {{entry.Path}}
        Заголовок правила: {{entry.Metadata.Title ?? "не указан"}}
        Logsource: {{entry.Metadata.Logsource ?? "не указан"}}
        Коммит: {{entry.Subject}}
        Примечание анализа: {{entry.ChangeNote}}

        Sanitized structural diff:
        {{detectionDiff}}

        Sanitized current detection structure after change:
        {{currentDetection}}
        """;
    }

    private static string BuildDetectionDiffPromptSection(DetectionChangeEntry entry)
    {
        if (entry.LogicLanguage == "diff")
        {
            return PrepareSummaryPromptContext(entry.PromptLogic);
        }

        if (entry.Kind == DetectionChangeKind.Deleted)
        {
            return "Блок detection удалён. Последний существовавший текст до удаления:\n"
                + PrepareSummaryPromptContext(entry.PromptLogic);
        }

        if (entry.Kind == DetectionChangeKind.Added)
        {
            return "Не применимо: правило добавлено целиком.";
        }

        return "Не применимо: блок detection добавлен без предыдущей версии.";
    }

    private static string PrepareSummaryPromptContext(string text)
    {
        var sanitizedLines = NormalizeLineEndings(text)
            .Split('\n')
            .Select(SanitizeSummaryPromptLine);

        return LimitPromptContext(string.Join('\n', sanitizedLines));
    }

    private static string SanitizeSummaryPromptLine(string line)
    {
        var sanitized = RemoveYamlCommentText(line);
        sanitized = UrlRegex().Replace(sanitized, "[url]");
        sanitized = Ipv4Regex().Replace(sanitized, "[ip]");
        sanitized = HashRegex().Replace(sanitized, "[hash]");
        sanitized = EncodedValueRegex().Replace(sanitized, "[encoded-value]");
        return QuotedLiteralRegex().Replace(sanitized, SanitizeQuotedLiteral);
    }

    private static string RemoveYamlCommentText(string line)
    {
        var trimmed = line.TrimStart(' ', '\t', '+', '-');
        if (trimmed.StartsWith('#'))
        {
            var prefixLength = line.Length - trimmed.Length;
            return line[..prefixLength] + "# [comment removed]";
        }

        var commentIndex = line.IndexOf(" #", StringComparison.Ordinal);
        return commentIndex >= 0 ? line[..commentIndex] + " # [comment removed]" : line;
    }

    private static string SanitizeQuotedLiteral(Match match)
    {
        var quote = match.Groups["quote"].Value;
        var value = match.Groups["value"].Value;

        if (IsPromptSensitiveLiteral(value))
        {
            return $"{quote}[redacted-literal]{quote}";
        }

        if (value.Length > 120)
        {
            return $"{quote}{value[..117]}...{quote}";
        }

        return match.Value;
    }

    private static bool IsPromptSensitiveLiteral(string value)
    {
        return value.Length > 180
            || UrlRegex().IsMatch(value)
            || Ipv4Regex().IsMatch(value)
            || HashRegex().IsMatch(value)
            || EncodedValueRegex().IsMatch(value)
            || value.Contains(';', StringComparison.Ordinal)
            || value.Contains("&&", StringComparison.Ordinal)
            || value.Contains("||", StringComparison.Ordinal)
            || value.Contains("$(", StringComparison.Ordinal)
            || value.Contains('`', StringComparison.Ordinal)
            || value.Contains(" | ", StringComparison.Ordinal)
            || value.Contains('<', StringComparison.Ordinal)
            || value.Contains('>', StringComparison.Ordinal);
    }

    private static string LimitPromptContext(string text)
    {
        return text.Length <= SummaryContextCharLimit
            ? text
            : text[..SummaryContextCharLimit] + "\n# ... truncated for OpenAI prompt context";
    }

    private static string GetRemoteBaseUrl(Repository repository)
    {
        var remoteUrl = repository.Network.Remotes["upstream"]?.Url
            ?? repository.Network.Remotes["origin"]?.Url
            ?? "https://github.com/SigmaHQ/sigma";

        if (remoteUrl.StartsWith("git@github.com:", StringComparison.OrdinalIgnoreCase))
        {
            remoteUrl = "https://github.com/" + remoteUrl["git@github.com:".Length..];
        }

        if (remoteUrl.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
        {
            remoteUrl = remoteUrl[..^4];
        }

        return remoteUrl.Replace('\\', '/');
    }

    private static string BuildCommitUrl(string? remoteBaseUrl, string commitSha)
    {
        return string.IsNullOrWhiteSpace(remoteBaseUrl) ? commitSha : $"{remoteBaseUrl}/commit/{commitSha}";
    }

    private static string? BuildPullRequestUrl(string? remoteBaseUrl, int? prNumber)
    {
        return prNumber is null || string.IsNullOrWhiteSpace(remoteBaseUrl) ? null : $"{remoteBaseUrl}/pull/{prNumber.Value}";
    }

    private static int? ExtractPullRequestNumber(Commit commit)
    {
        var message = commit.Message ?? commit.MessageShort ?? string.Empty;
        var match = PullRequestRegex().Match(message);
        return match.Success ? int.Parse(match.Groups["number"].Value, CultureInfo.InvariantCulture) : null;
    }

    private static string FirstLine(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return NormalizeLineEndings(value).Split('\n', 2)[0].Trim();
    }

    private static string SingleLine(string value)
    {
        return Regex.Replace(NormalizeLineEndings(value), @"\s+", " ").Trim();
    }

    private static string ResolveOutputPath(string repoPath, string outputPath)
    {
        return Path.IsPathRooted(outputPath) ? outputPath : Path.GetFullPath(Path.Combine(repoPath, outputPath));
    }

    [GeneratedRegex(@"#(?<number>\d+)")]
    private static partial Regex PullRequestRegex();

    [GeneratedRegex(@"https?://\S+", RegexOptions.IgnoreCase)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b")]
    private static partial Regex Ipv4Regex();

    [GeneratedRegex(@"\b[0-9a-fA-F]{32,}\b")]
    private static partial Regex HashRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/])")]
    private static partial Regex EncodedValueRegex();

    [GeneratedRegex(@"(?<quote>['""])(?<value>.*?)(\k<quote>)")]
    private static partial Regex QuotedLiteralRegex();
}

[Description("Generate an HTML report of Sigma detection-logic changes.")]
internal sealed class GenerateReportCommand : AsyncCommand<GenerateReportSettings>
{
    protected override async Task<int> ExecuteAsync(
        CommandContext context,
        GenerateReportSettings settings,
        CancellationToken cancellationToken)
    {
        return await Program.RunAsync(settings.ToCliOptions(), cancellationToken);
    }
}

internal sealed class GenerateReportSettings : CommandSettings
{
    [CommandOption("--repo <PATH>")]
    [Description("Path to the Sigma repository.")]
    [DefaultValue(".")]
    public string RepoPath { get; init; } = ".";

    [CommandOption("--output <PATH>")]
    [Description("HTML output path. Relative paths are resolved from --repo.")]
    [DefaultValue("docs/detection-changes.html")]
    public string OutputPath { get; init; } = "docs/detection-changes.html";

    [CommandOption("--since <BOUNDARY>")]
    [Description("Start boundary as an ISO date/date-time or Git ref.")]
    [DefaultValue("r2026-07-01")]
    public string Since { get; init; } = "r2026-07-01";

    [CommandOption("--until <BOUNDARY>")]
    [Description("End boundary as an ISO date/date-time or Git ref. Defaults to upstream/master when present, otherwise HEAD.")]
    public string? Until { get; init; }

    [CommandOption("--openai-api-key <KEY>")]
    [Description("OpenAI API key. When provided, short Russian summaries are added.")]
    public string? OpenAiApiKey { get; init; }

    [CommandOption("--openai-model <MODEL>")]
    [Description("OpenAI model used for summaries.")]
    [DefaultValue("gpt-5.6-luna")]
    public string OpenAiModel { get; init; } = "gpt-5.6-luna";

    [CommandOption("--include-modified <VALUE>")]
    [Description("Include modified/deleted/renamed rules whose detection block changed.")]
    [DefaultValue(true)]
    public bool IncludeModified { get; init; } = true;

    [CommandOption("--include-unsupported <VALUE>")]
    [Description("Include rules under unsupported/.")]
    [DefaultValue(true)]
    public bool IncludeUnsupported { get; init; } = true;

    [CommandOption("--max-detection-lines <COUNT>")]
    [Description("Maximum number of detection/diff lines per row. Omit for no limit.")]
    public int? MaxDetectionLines { get; init; }

    public override ValidationResult Validate()
    {
        return MaxDetectionLines is <= 0
            ? ValidationResult.Error("--max-detection-lines must be a positive integer.")
            : ValidationResult.Success();
    }

    public CliOptions ToCliOptions()
    {
        return new CliOptions(
            RepoPath: Path.GetFullPath(RepoPath),
            OutputPath: OutputPath,
            Since: Since,
            Until: Until,
            OpenAiApiKey: OpenAiApiKey,
            OpenAiModel: OpenAiModel,
            IncludeModified: IncludeModified,
            IncludeUnsupported: IncludeUnsupported,
            MaxDetectionLines: MaxDetectionLines);
    }
}

internal sealed record CliOptions(
    string RepoPath,
    string OutputPath,
    string Since,
    string? Until,
    string? OpenAiApiKey,
    string OpenAiModel,
    bool IncludeModified,
    bool IncludeUnsupported,
    int? MaxDetectionLines);

internal sealed record RunSummary(
    int EntryCount,
    int CommitCount,
    string OutputPath,
    string RangeText);

internal sealed record OpenAiSummaryWarning(string Path, string ShortSha, string Message);

internal sealed record Boundary(
    string Display,
    Commit? Commit,
    DateTimeOffset? StartInclusive,
    DateTimeOffset? EndExclusive);

internal sealed record AnalysisRange(Boundary Since, Boundary Until, Commit TraversalTip)
{
    public string DisplayText => $"{Since.Display}..{Until.Display}";
}

internal enum BoundaryRole
{
    Since,
    Until
}

internal enum DetectionChangeKind
{
    Added,
    Modified,
    Renamed,
    Deleted
}

internal sealed record DetectionChangeEntry(
    DetectionChangeKind Kind,
    string CommitSha,
    string ShortSha,
    DateTimeOffset CommitDate,
    string Subject,
    int? PrNumber,
    string CommitUrl,
    string? PullRequestUrl,
    string Path,
    string? OldPath,
    RuleMetadata Metadata,
    string Logic,
    string LogicLanguage,
    string PromptLogic,
    string? CurrentDetection,
    string? PromptCurrentDetection,
    bool IsCurrentDetectionUnavailable,
    string ChangeNote,
    bool IsTruncated,
    bool IsCurrentDetectionTruncated,
    string? RussianSummary)
{
    public string KindLabelRu => Kind switch
    {
        DetectionChangeKind.Added => "Добавлено",
        DetectionChangeKind.Modified => "Изменено",
        DetectionChangeKind.Renamed => "Переименовано",
        DetectionChangeKind.Deleted => "Удалено",
        _ => Kind.ToString()
    };
}

internal sealed record RuleMetadata(
    string? Title,
    string? Logsource,
    string? Level,
    IReadOnlyList<string> Tags)
{
    public static RuleMetadata Empty { get; } = new(null, null, null, []);

    public static RuleMetadata Read(string? yaml)
    {
        if (string.IsNullOrWhiteSpace(yaml))
        {
            return Empty;
        }

        try
        {
            var stream = new YamlStream();
            stream.Load(new StringReader(yaml));

            if (stream.Documents.Count == 0 || stream.Documents[0].RootNode is not YamlMappingNode root)
            {
                return Empty;
            }

            var title = TryGetScalar(root, "title");
            var level = TryGetScalar(root, "level");
            var tags = TryGetStringList(root, "tags");
            var logsource = TryGetMapping(root, "logsource") is { } logsourceNode
                ? FormatLogsource(logsourceNode)
                : null;

            return new RuleMetadata(title, logsource, level, tags);
        }
        catch
        {
            return Empty;
        }
    }

    private static string? TryGetScalar(YamlMappingNode root, string key)
    {
        return root.Children.TryGetValue(new YamlScalarNode(key), out var node) && node is YamlScalarNode scalar
            ? Compact(scalar.Value)
            : null;
    }

    private static YamlMappingNode? TryGetMapping(YamlMappingNode root, string key)
    {
        return root.Children.TryGetValue(new YamlScalarNode(key), out var node) && node is YamlMappingNode mapping
            ? mapping
            : null;
    }

    private static IReadOnlyList<string> TryGetStringList(YamlMappingNode root, string key)
    {
        if (!root.Children.TryGetValue(new YamlScalarNode(key), out var node))
        {
            return [];
        }

        return node switch
        {
            YamlSequenceNode sequence => sequence.Children.OfType<YamlScalarNode>()
                .Select(item => item.Value)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Cast<string>()
                .ToList(),
            YamlScalarNode scalar when !string.IsNullOrWhiteSpace(scalar.Value) => [scalar.Value],
            _ => []
        };
    }

    private static string? FormatLogsource(YamlMappingNode logsource)
    {
        var parts = logsource.Children
            .Select(pair => new
            {
                Key = (pair.Key as YamlScalarNode)?.Value,
                Value = pair.Value is YamlScalarNode scalar ? Compact(scalar.Value) : null
            })
            .Where(pair => !string.IsNullOrWhiteSpace(pair.Key) && !string.IsNullOrWhiteSpace(pair.Value))
            .Select(pair => $"{pair.Key}: {pair.Value}")
            .ToList();

        return parts.Count == 0 ? null : string.Join(", ", parts);
    }

    private static string? Compact(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? null
            : Regex.Replace(ProgramLineEndings.Normalize(value), @"\s+", " ").Trim();
    }
}

internal sealed record DetectionBlock(string Text)
{
    public static DetectionBlock? Extract(string? yaml)
    {
        if (string.IsNullOrWhiteSpace(yaml))
        {
            return null;
        }

        var lines = ProgramLineEndings.Normalize(yaml).Split('\n');
        var detectionIndex = Array.FindIndex(lines, line => Regex.IsMatch(line, @"^detection:\s*(#.*)?$"));

        if (detectionIndex < 0)
        {
            return null;
        }

        var endIndex = lines.Length;

        for (var index = detectionIndex + 1; index < lines.Length; index++)
        {
            var line = lines[index];
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith(' ') || line.StartsWith('\t') || line.TrimStart().StartsWith('#'))
            {
                continue;
            }

            endIndex = index;
            break;
        }

        var text = string.Join('\n', lines[detectionIndex..endIndex]).TrimEnd();
        return string.IsNullOrWhiteSpace(text) ? null : new DetectionBlock(text);
    }
}

internal static class ProgramLineEndings
{
    public static string Normalize(string text)
    {
        return text.Replace("\r\n", "\n").Replace('\r', '\n');
    }
}

internal static class DetectionDiff
{
    public static string Build(string oldText, string newText, int contextLines = 2)
    {
        var oldLines = ProgramLineEndings.Normalize(oldText).Split('\n');
        var newLines = ProgramLineEndings.Normalize(newText).Split('\n');
        var operations = DiffOperations(oldLines, newLines);
        var include = new bool[operations.Count];

        for (var index = 0; index < operations.Count; index++)
        {
            if (operations[index].Kind == DiffKind.Unchanged)
            {
                continue;
            }

            var start = Math.Max(0, index - contextLines);
            var end = Math.Min(operations.Count - 1, index + contextLines);
            for (var contextIndex = start; contextIndex <= end; contextIndex++)
            {
                include[contextIndex] = true;
            }
        }

        var builder = new StringBuilder();
        var inHunk = false;

        for (var index = 0; index < operations.Count; index++)
        {
            if (!include[index])
            {
                if (inHunk)
                {
                    inHunk = false;
                }

                continue;
            }

            if (!inHunk)
            {
                if (builder.Length > 0)
                {
                    builder.AppendLine();
                }

                builder.AppendLine("@@");
                inHunk = true;
            }

            var prefix = operations[index].Kind switch
            {
                DiffKind.Added => '+',
                DiffKind.Removed => '-',
                _ => ' '
            };

            builder.Append(prefix).AppendLine(operations[index].Line);
        }

        return builder.Length == 0 ? "# detection block changed, but no line diff was produced" : builder.ToString().TrimEnd();
    }

    private static List<DiffOperation> DiffOperations(IReadOnlyList<string> oldLines, IReadOnlyList<string> newLines)
    {
        var table = new int[oldLines.Count + 1, newLines.Count + 1];

        for (var oldIndex = oldLines.Count - 1; oldIndex >= 0; oldIndex--)
        {
            for (var newIndex = newLines.Count - 1; newIndex >= 0; newIndex--)
            {
                table[oldIndex, newIndex] = oldLines[oldIndex] == newLines[newIndex]
                    ? table[oldIndex + 1, newIndex + 1] + 1
                    : Math.Max(table[oldIndex + 1, newIndex], table[oldIndex, newIndex + 1]);
            }
        }

        var operations = new List<DiffOperation>();
        var i = 0;
        var j = 0;

        while (i < oldLines.Count && j < newLines.Count)
        {
            if (oldLines[i] == newLines[j])
            {
                operations.Add(new DiffOperation(DiffKind.Unchanged, oldLines[i]));
                i++;
                j++;
            }
            else if (table[i + 1, j] >= table[i, j + 1])
            {
                operations.Add(new DiffOperation(DiffKind.Removed, oldLines[i]));
                i++;
            }
            else
            {
                operations.Add(new DiffOperation(DiffKind.Added, newLines[j]));
                j++;
            }
        }

        while (i < oldLines.Count)
        {
            operations.Add(new DiffOperation(DiffKind.Removed, oldLines[i++]));
        }

        while (j < newLines.Count)
        {
            operations.Add(new DiffOperation(DiffKind.Added, newLines[j++]));
        }

        return operations;
    }

    private sealed record DiffOperation(DiffKind Kind, string Line);

    private enum DiffKind
    {
        Unchanged,
        Added,
        Removed
    }
}

internal static class DetectionChangeNotes
{
    public static string Build(string? oldText, string? newText, ChangeKind changeKind)
    {
        if (changeKind == ChangeKind.Deleted || newText is null)
        {
            return "Удалён блок detection вместе с правилом.";
        }

        if (oldText is null)
        {
            return "Добавлен блок detection.";
        }

        var oldInfo = DetectionShape.Read(oldText);
        var newInfo = DetectionShape.Read(newText);
        var notes = new List<string>();

        if (!string.Equals(oldInfo.Condition, newInfo.Condition, StringComparison.Ordinal))
        {
            notes.Add($"condition: {FormatValue(oldInfo.Condition)} -> {FormatValue(newInfo.Condition)}");
        }

        AddSetNote(notes, "добавлены selector/filter", newInfo.Keys.Except(oldInfo.Keys).ToList());
        AddSetNote(notes, "удалены selector/filter", oldInfo.Keys.Except(newInfo.Keys).ToList());

        return notes.Count == 0
            ? "Изменились значения внутри существующих selector/filter."
            : string.Join("; ", notes) + ".";
    }

    private static void AddSetNote(List<string> notes, string label, IReadOnlyList<string> values)
    {
        if (values.Count > 0)
        {
            notes.Add($"{label}: {string.Join(", ", values)}");
        }
    }

    private static string FormatValue(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? "<empty>" : value;
    }

    private sealed record DetectionShape(IReadOnlySet<string> Keys, string? Condition)
    {
        public static DetectionShape Read(string text)
        {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            string? condition = null;
            var lines = ProgramLineEndings.Normalize(text).Split('\n');

            foreach (var line in lines.Skip(1))
            {
                if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#'))
                {
                    continue;
                }

                var indent = line.Length - line.TrimStart(' ', '\t').Length;
                if (indent is not (2 or 4))
                {
                    continue;
                }

                var trimmed = line.Trim();
                var separatorIndex = trimmed.IndexOf(':', StringComparison.Ordinal);
                if (separatorIndex <= 0)
                {
                    continue;
                }

                var key = trimmed[..separatorIndex];
                if (key == "condition")
                {
                    condition = trimmed[(separatorIndex + 1)..].Trim();
                }
                else if (!key.StartsWith('-'))
                {
                    keys.Add(key);
                }
            }

            return new DetectionShape(keys, condition);
        }
    }
}

internal static class HtmlReport
{
    public static string Render(
        CliOptions options,
        AnalysisRange range,
        string remoteBaseUrl,
        IReadOnlyList<DetectionChangeEntry> entries)
    {
        var added = entries.Where(entry => entry.Kind == DetectionChangeKind.Added).ToList();
        var changed = entries.Where(entry => entry.Kind != DetectionChangeKind.Added).ToList();

        var model = new HtmlReportModel(
            RepoPath: Html(options.RepoPath),
            Range: Html(range.DisplayText),
            TraversalCommitUrl: HtmlAttribute($"{remoteBaseUrl}/commit/{range.TraversalTip.Sha}"),
            TraversalCommitShortSha: Html(range.TraversalTip.Sha[..10]),
            GeneratedAt: Html(DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)),
            OpenAiSummaryStatus: Html(!string.IsNullOrWhiteSpace(options.OpenAiApiKey) ? "enabled" : "disabled"),
            IncludeModified: Html(options.IncludeModified.ToString(CultureInfo.InvariantCulture)),
            IncludeUnsupported: Html(options.IncludeUnsupported.ToString(CultureInfo.InvariantCulture)),
            HasMaxDetectionLines: options.MaxDetectionLines is not null,
            MaxDetectionLines: options.MaxDetectionLines is { } maxDetectionLines ? Html(maxDetectionLines.ToString(CultureInfo.InvariantCulture)) : null,
            Tables:
            [
                new HtmlReportTable("Новая детектирующая логика", added.Select(ToHtmlEntry).ToList()),
                new HtmlReportTable("Изменённая детектирующая логика", changed.Select(ToHtmlEntry).ToList())
            ]);

        var templatePath = FindTemplatePath(options.RepoPath);
        var templateText = File.ReadAllText(templatePath, Encoding.UTF8);
        var template = Template.Parse(templateText, templatePath);

        if (template.HasErrors)
        {
            throw new InvalidOperationException("Unable to parse HTML report template: " + string.Join("; ", template.Messages));
        }

        return template.Render(model);
    }

    private static HtmlReportEntry ToHtmlEntry(DetectionChangeEntry entry)
    {
        return new HtmlReportEntry(
            CommitDate: Html(entry.CommitDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)),
            PullRequestUrl: entry.PullRequestUrl is null ? null : HtmlAttribute(entry.PullRequestUrl),
            PrNumber: entry.PrNumber?.ToString(CultureInfo.InvariantCulture),
            CommitUrl: HtmlAttribute(entry.CommitUrl),
            ShortSha: Html(entry.ShortSha),
            Subject: Html(entry.Subject),
            KindLabel: Html(entry.KindLabelRu),
            Path: Html(entry.Path),
            OldPath: entry.OldPath is null ? null : Html(entry.OldPath),
            Title: string.IsNullOrWhiteSpace(entry.Metadata.Title) ? null : Html(entry.Metadata.Title!),
            Logsource: string.IsNullOrWhiteSpace(entry.Metadata.Logsource) ? null : Html(entry.Metadata.Logsource!),
            Level: string.IsNullOrWhiteSpace(entry.Metadata.Level) ? null : Html(entry.Metadata.Level!),
            Tags: entry.Metadata.Tags.Count == 0 ? null : Html(string.Join(", ", entry.Metadata.Tags.Take(8))),
            RussianSummary: string.IsNullOrWhiteSpace(entry.RussianSummary) ? null : Html(entry.RussianSummary!),
            ChangeNote: Html(entry.ChangeNote),
            Logic: Html(entry.Logic),
            CurrentDetection: entry.CurrentDetection is null ? null : Html(entry.CurrentDetection),
            IsCurrentDetectionUnavailable: entry.IsCurrentDetectionUnavailable,
            IsTruncated: entry.IsTruncated,
            IsCurrentDetectionTruncated: entry.IsCurrentDetectionTruncated);
    }

    private static string FindTemplatePath(string repoPath)
    {
        var publishedPath = Path.Combine(AppContext.BaseDirectory, "Templates", "report.html.scriban");
        if (File.Exists(publishedPath))
        {
            return publishedPath;
        }

        var sourcePath = Path.Combine(repoPath, "tools", "SigmaDetectionChanges", "Templates", "report.html.scriban");
        if (File.Exists(sourcePath))
        {
            return sourcePath;
        }

        throw new FileNotFoundException("Unable to find HTML report template.", publishedPath);
    }

    private static string Html(string value)
    {
        return WebUtility.HtmlEncode(value);
    }

    private static string HtmlAttribute(string value)
    {
        return Html(value).Replace("\"", "&quot;", StringComparison.Ordinal);
    }
}

internal sealed record HtmlReportModel(
    string RepoPath,
    string Range,
    string TraversalCommitUrl,
    string TraversalCommitShortSha,
    string GeneratedAt,
    string OpenAiSummaryStatus,
    string IncludeModified,
    string IncludeUnsupported,
    bool HasMaxDetectionLines,
    string? MaxDetectionLines,
    IReadOnlyList<HtmlReportTable> Tables);

internal sealed record HtmlReportTable(string Title, IReadOnlyList<HtmlReportEntry> Entries)
{
    public bool HasEntries => Entries.Count > 0;
}

internal sealed record HtmlReportEntry(
    string CommitDate,
    string? PullRequestUrl,
    string? PrNumber,
    string CommitUrl,
    string ShortSha,
    string Subject,
    string KindLabel,
    string Path,
    string? OldPath,
    string? Title,
    string? Logsource,
    string? Level,
    string? Tags,
    string? RussianSummary,
    string ChangeNote,
    string Logic,
    string? CurrentDetection,
    bool IsCurrentDetectionUnavailable,
    bool IsTruncated,
    bool IsCurrentDetectionTruncated);
