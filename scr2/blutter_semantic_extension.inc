// Snapshot metadata only. This block never invokes a target Dart function.
// Included inside Blutter's main(), while app's Dart handle scope is active.
{
    std::ofstream meta((outDir / "semantic.tsv").string());
    meta << "format\tapk-defense.flutter-metadata/v1\n";
    meta << "builtin\tstring\t" << dart::kOneByteStringCid << '\n';
    meta << "builtin\tlist\t" << dart::kGrowableObjectArrayCid << '\n';
    meta << "builtin\tuint8\t" << dart::kTypedDataUint8ArrayCid << '\n';
    const auto &pool = app.GetObjectPool();
    auto &object = dart::Object::Handle();
    for (intptr_t i = 0; i < pool.Length(); ++i) {
        if (i >= 1000000) throw std::runtime_error("semantic pool limit");
        if (pool.TypeAt(i) != dart::ObjectPool::EntryType::kTaggedObject) continue;
        object = pool.ObjectAt(i);
        const auto offset = dart::ObjectPool::OffsetFromIndex(i) + 1;
        meta << "object\t" << offset << '\t' << object.GetClassId() << '\n';
        if (object.IsField()) {
            const auto &field = dart::Field::Cast(object);
            intptr_t entry = 0;
            if (field.HasInitializerFunction()) {
                const auto &fn = dart::Function::Handle(field.InitializerFunction());
                if (!fn.IsNull()) entry = fn.entry_point() - app.base();
            }
            meta << "field\t" << offset << '\t' << field.TargetOffset() << '\t'
                 << field.is_static() << '\t' << entry << '\n';
        }
    }
    auto *ig = dart::IsolateGroup::Current();
    const auto *dispatch = ig->dispatch_table();
    if (dispatch) {
        if (dispatch->length() > 1000000) throw std::runtime_error("semantic dispatch limit");
        const auto *origin = dispatch->ArrayOrigin();
        for (intptr_t i = 0; i < dispatch->length(); ++i) {
            const auto relative = i - dart::DispatchTable::kOriginElement;
            const auto address = origin[relative];
            if (address) meta << "dispatch\t" << relative << '\t' << address - app.base() << '\n';
        }
    }
}
